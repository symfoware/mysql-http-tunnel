import os
import socket
import socketserver
import struct
import zlib
import logging
import configparser
import datetime

import json
import urllib.request
import urllib.parse

CONFIG_FILE_NAME = 'default.cfg'

COM_QUERY = 0x03
COM_PING = 0x0e
COM_QUIT = 0x01
COM_STMT_PREPARE = 0x16
COM_STMT_EXECUTE = 0x17
COM_STMT_CLOSE = 0x19

# ------------------------------------------------------------------
# TCPServer
class MySQLHTServer(socketserver.TCPServer):
    allow_reuse_address = True

class MySQLHTHandler(socketserver.BaseRequestHandler):

    def setup(self):
        # 設定値読み込み
        self.servers = {}
        config = configparser.ConfigParser()
        config.read_file(open(CONFIG_FILE_NAME))

        for section in config.sections():
            self.load_section(section, config)

        
    # 必須項目をチェックしながら設定ファイルをロード
    def load_section(self, section, config):
        keys = ['endpoint', 'host', 'database', 'charset','user','password']
        defaults = {'charset':'utf8mb4', 'password':''}
        setting = {}
        for key in keys:
            setting[key] = config.get(section, key, fallback=None)
            if setting[key]:
                continue
            if key in defaults:
                setting[key] = defaults[key]
                continue
            logging.error(f'設定ファイル {section}:{key}項目が未設定です 設定を除外します')
            return

        self.servers[section] = setting



    def handle(self):
        # ---------------------------------------------------------
        # Connection Phase
        # Protocol::HandshakeV10
        handshake = HandshakePacket(Sequence()).make()
        logging.info('--> HandshakeV10')
        self.request.sendall(handshake)
        
        # Protocol::HandshakeResponse41
        logging.info('<-- HandshakeResponse41')
        rec = self.request.recv(8192)
        client = Client(rec)
        
        # ユーザー名のセクションがcfgに存在するかチェック
        if client.vuser in self.servers:
            logging.info('--> OK')
            client.set_setting(self.servers[client.vuser])
            self.request.sendall(OkPacket(Sequence(client.sequence)).make())
        else:
            logging.info('--> USER ERROR')
            error = ErrorPacket(Sequence(client.sequence)) \
                        .make(1045, 'HY000', 'user not found default.cfg')
            
            self.request.sendall(error)
            logging.info('Close Connection.')
            return

        
        # ---------------------------------------------------------
        # Command Phase
        while True:
            # クライアントからのコマンド受信
            rec = self.request.recv(8192)
            # リクエストの解析
            request = Request(rec, client)
            # コマンドに対応するレスポンス生成
            response = self.execute_command(request, client)
            if response:
                self.request.sendall(response)

            if request.command == COM_QUIT:
                logging.info('Bye.')
                break

        logging.info('Close Connection.')


    # コマンドに対応するレスポンス生成
    def execute_command(self, request, client):
        response = None
        # -- Text Protocol
        if request.command == COM_QUERY: # COM_QUERY
            response = self.execute_query(request, client)
        
        # -- Prepared Statements
        elif request.command == COM_STMT_PREPARE: # COM_STMT_PREPARE
            response = self.execute_prepare(request, client)

        elif request.command == COM_STMT_EXECUTE: # COM_STMT_EXECUTE
            request.query = 'SELECT id,name,email FROM users WHERE id = 2'
            response = self.execute_prepare_query(request, client)

        elif request.command == COM_STMT_CLOSE: # COM_STMT_CLOSE
            client.prepare = None
            response = None

        # SQL実行以外は一律OKパケットを応答
        else:
            logging.info('--> OK')
            response = OkPacket(Sequence(request.sequence)).make()

        return response


    # クエリー実行
    def execute_query(self, request, client):
        
        seq = Sequence(request.sequence)
        # proxy.php経由でSQL文実行
        result = self.fetch(client, request.query)
        logging.debug(result)
        
        if result['state']:
            # ERR_Packetを返却
            logging.info('--> Error')
            return ErrorPacket(seq).make(result['code'], result['state'], result['message'])

        # カラム数がない場合はOKパケット返信
        if not result['cols']:
            logging.info('--> OK')
            return OkPacket(seq).make(affected=result['affected'], last_insert_id=result['last_insert_id'])
        
        logging.info('--> Query Result')

        body = bytearray()
        # column_count
        body.extend(ColumnCountPacket(seq).make(len(result['cols'])))
        
        # field packet
        for col in result['cols']:
            body.extend(FieldPacket(seq).make(client, col))

        # CLIENT_DEPRECATE_EOFがoffならcolとrowの間にokパケットを挟む
        if not client.deprecate_eof:
            body.extend(OkPacket(seq).make(eof=True))

        # row packet
        for row in result['rows']:
            body.extend(RowPacket(seq).make(row))

        # intermediate eof
        if not client.deprecate_eof:
            # CLIENT_DEPRECATE_EOFがoffならokパケットで応答
            body.extend(OkPacket(seq).make(eof=True))
        else:
            body.extend(EofPacket(seq).make())

        return body

    
    # プリペアードステートメント実行
    def execute_prepare_query(self, request, client):

        seq = Sequence(request.sequence)
        # proxy.php経由でSQL文実行
        result = self.fetch(client, client.prepare['query'], request.binds)
        
        if result['state']:
            # ERR_Packetを返却
            logging.info('--> Error')
            return ErrorPacket(seq).make(result['code'], result['state'], result['message'])

        # カラム数がない場合はOKパケット返信
        if not result['cols']:
            logging.info('--> OK')
            return OkPacket(seq).make(affected=result['affected'], last_insert_id=result['last_insert_id'])
        
        logging.info('--> Prepare Result')

        body = bytearray()
        # column_count
        body.extend(ColumnCountPacket(seq).make(len(result['cols'])))
        
        # field packet
        for col in result['cols']:
            body.extend(FieldPacket(seq).make(client, col))

        # intermediate eof
        body.extend(EofPacket(seq).make())

        # row packet
        for row in result['rows']:
            body.extend(BinaryRowPacket(seq).make(row, result['cols']))

        # response eof
        body.extend(EofPacket(seq).make())
            

        return body

    
    # プリペアードステートメント解析
    def execute_prepare(self, request, client):

        logging.info('--> Prepare OK')

        seq = Sequence(request.sequence)

        body = bytearray()

        # パラメーター数は仮で「?」をカウント
        # @todo カウント方法を検討
        num_params = request.query.count('?')
        num_columns = 1
        client.prepare = {
            'query': request.query,
            'num_params': num_params
        }
        # prepare ok
        body.extend(PrepareOkPacket(seq).make(client, num_columns, num_params))

        # バインドするカラム数の枠が必要
        # params
        col = {'table':'', 'name':'?', 'len':21, 'native_type':'LONGLONG', 'flags':[], 'precision':0} # ダミーの列定義
        for i in range(num_params):
            body.extend(FieldPacket(seq).make(client, col))

        # intermediate eof
        body.extend(EofPacket(seq).make())
        # field packet
        # num_columnsと一致させる
        # 結果セットを返すクエリーなのに0だとドライバー側でパケット解析に失敗しエラーになる
        body.extend(FieldPacket(seq).make(client, col))

        # response eof
        body.extend(EofPacket(seq).make())

        return body




    # サーバー上のPHPを呼び出しクエリー実行
    def fetch(self, client, query, binds=None):
        url = client.endpoint
        # 送信パラメーター
        data = {
            'host': client.host,
            'database': client.database,
            'charset': client.charset,
            'user': client.user,
            'password': client.password,
            'query': query,
            'mode' : 'text'
        }
        if binds:
            data['binds'] = binds
            data['mode'] = 'prepare'

        # 送信パラメーターをjsonに変換
        jsondata = json.dumps(data)
        # zip圧縮
        zipdata = zlib.compress(jsondata.encode())

        try:
            # postリクエストを実行
            with urllib.request.urlopen(url, zipdata) as response:
                # zip解凍してjsonデコード
                body = zlib.decompress(response.read()).decode('utf-8')
                result = json.loads(body)
                return result

        except Exception as e:
            logging.error(e)
            logging.error(f'Query: ' + query)
            return {
                'state': 0,
                'cols': [],
                'rows': [],
                'last_insert_id': 0,
                'affected': 0
            }




# ------------------------------------------------------------------
class Sequence(object):
    def __init__(self, start=-1):
        self.seq = start
    
    def next(self):
        self.seq += 1
        if 0xff < self.seq:
            self.seq = 0
        return self.seq


class Packet(object):
    def __init__(self, seq):
        self.body = bytearray()
        self.seq = seq

    def extend(self, val):
        self.body.extend(val)

    def pack(self):
        # データ長(3) + シーケンス番号(0)をまとめて出力
        return struct.pack('<I', len(self.body))[0:3] + struct.pack('<B', self.seq.next()) + self.body

    def string_lenenc(self, data):
        # NULL is sent as 0xFB
        if data == None:
            return struct.pack('<B', 0xfb) 

        value = str(data).encode()
        size = len(value)
        # size(1byte) + 実データの形式で書き込む
        # 0xfbがnullで予約されていることから、sizeが0xfb未満なら以下の挙動になると予測
        if size < 0xfb:
            return struct.pack('<B', size) + value
        # 通信データを解析する感じ、sizeが1byteに収まらない場合は0xfcに続いて2byteでsizeを書き込んだのち実データを書き込む模様
        elif size < 0xffff:
            return struct.pack('<B', 0xfc) + struct.pack('<H', size) + value
        
        # これ以降予測
        elif size < 0xffffff:
            return struct.pack('<B', 0xfd) + struct.pack('<I', size)[:3] + value

        return struct.pack('<B', 0xfe) + struct.pack('<I', size) + value


# Protocol::HandshakeV10
class HandshakePacket(Packet):
    def make(self):
        # protocol version int(1) 10固定
        self.extend(struct.pack('<B', 10))
        
        # server version string(nul)
        self.extend(b'8.0.42-mysql') # d.d.dのバージョン情報が必要
        self.extend(struct.pack('<B', 0))
        # thread id int(4)
        self.extend(struct.pack('<I', 1))
        # auth-plugin-data-part-1 string(8)
        self.extend(b'salt1234') # 適当な文字を指定
        # filler int(1)
        self.extend(struct.pack('<B', 0))
        # capability_flags_1 int(2)
        self.extend(struct.pack('<H', 0xffff - 2048))  # SSL未使用(CLIENT_SSL:2048)
        # character_set int(1)
        self.extend(struct.pack('<B', 0xff))
        # status_flags int(2)
        self.extend(struct.pack('<H', 2)) # SERVER_STATUS_AUTOCOMMIT
        # capability_flags_2 int(2)
        self.extend(struct.pack('<H', 0xdfff))
        # auth_plugin_data_len int(1)
        auth_plugin_name = b'mysql_native_password'
        self.extend(struct.pack('<B', len(auth_plugin_name)))
        # reserved 10
        for i in range(10):
            self.extend(struct.pack('<B', 0))
        # auth-plugin-data-part-2
        self.extend(b'123456789012') # 適当な文字を指定(桁数は暗号化方式により変動?)
        self.extend(struct.pack('<B', 0))
        # auth_plugin_name
        self.extend(auth_plugin_name)
        self.extend(struct.pack('<B', 0))
        
        return self.pack()


class OkPacket(Packet):
    def make(self, eof=False, affected=0, last_insert_id=0):
        # header 0x00 or 0xFE the OK packet header
        if eof:
            self.extend(struct.pack('<B', 0xfe))
        else:
            self.extend(struct.pack('<B', 0))

        self.extend(struct.pack('<B', affected)) # affected rows
        self.extend(struct.pack('<B', last_insert_id)) # last insert-id

        self.extend(struct.pack('<H', 2)) # SERVER_STATUS_flags_enum
        self.extend(struct.pack('<H', 0)) # number of warnings

        return self.pack()


class ErrorPacket(Packet):
    def make(self, code, state, message):        
        self.extend(struct.pack('<B', 0xff)) # 0xFF ERR packet header
        self.extend(struct.pack('<H', code)) # error_code

        self.extend(struct.pack('<B', 0x23)) # sql_state_marker 0x23(#)固定
        self.extend(state.encode()) # sql_state
        self.extend(message.encode())# error_message

        return self.pack()


# 結果セットの列数
class ColumnCountPacket(Packet):
    def make(self, column_count):
        self.extend(struct.pack('<B', column_count))
        return self.pack()



# 列名情報
class FieldPacket(Packet):
    def make(self, client, col):
        # catalog
        self.extend(self.string_lenenc('def')) # def固定
        # schema
        self.extend(self.string_lenenc(client.database)) # selectを実行したデータベース名と一致させる
        # table
        self.extend(self.string_lenenc(col['table']))
        # org_table
        self.extend(self.string_lenenc(col['table']))
        # name
        self.extend(self.string_lenenc(col['name']))
        # org_name
        self.extend(self.string_lenenc(col['name']))

        # length
        self.extend(struct.pack('<B', 0x0c))
        # character_set
        self.extend(struct.pack('<H', 0x00ff))
        # column_length
        self.extend(struct.pack('<I', col['len']))
        # type
        self.extend(struct.pack('<B', self.field_type(col['native_type'])))
        # flags
        self.extend(struct.pack('<H', self.field_flag(col['flags'])))
        # decimals
        self.extend(struct.pack('<B', col['precision']))
        # reserved
        self.extend(struct.pack('<B', 0))
        self.extend(struct.pack('<B', 0))
        # default value
        self.extend(struct.pack('<B', 0))

        return self.pack()


    def field_type(self, native_type):
        types = {
            'DECIMAL':0, 'TINY':1, 'SHORT':2, 'LONG':3, 'FLOAT':4, 'DOUBLE':5,
            'NULL':6, 'TIMESTAMP':7, 'LONGLONG':8, 'INT24':9, 'DATE':10, 'TIME':11, 'DATETIME':12,
            'YEAR':13, 'NEWDATE':14, 'VARCHAR':15, 'BIT':16, 'TIMESTAMP2':17, 'DATETIME2':18,
            'TIME2':19, 'TYPED_ARRAY':20, 'VECTOR':242, 'INVALID':243, 'BOOL':244, 'JSON':245,
            'NEWDECIMAL':246, 'ENUM':247, 'SET':248, 'TINY_BLOB':249, 'EDIUM_BLOB':250, 'LONG_BLOB':251,
            'BLOB':252, 'VAR_STRING':253, 'STRING':254, 'GEOMETRY':255
        }

        if native_type in types:
            return types[native_type]

        logging.error('UNKOWN TYPE ' + native_type)
        return 0


    def field_flag(self, flags):
        flag_values = {
           'not_null':1,  'primary_key':2, 'unique_key':4, 'multiple_key':8, 'blob': 16,
           'unsigned':32, 'zerofill':64, 'binary':128
        }

        flag = 0
        for k, v in flag_values.items():
            if k in flags:
                flag += v

        return flag


# 行データパケット
class RowPacket(Packet):
    def make(self, row):
        # row value NULL is sent as 0xFB
        for data in row:
            self.extend(self.string_lenenc(data))

        return self.pack()


class BinaryRowPacket(Packet):
    def make(self, row, cols):
        
        self.extend(struct.pack('<B', 0)) # ok
        nulls = self.calcnull(row)
        for n in nulls: # null bitmap
            self.extend(struct.pack('<B', n))

        for data, col in zip(row, cols):
            if not data: # NULLは読み飛ばし
                continue

            ntype = col['native_type']
            if ntype == 'LONGLONG': # 8 bytes
                self.extend(struct.pack('<Q', int(data)))
            elif ntype == 'LONG': # 4 bytes
                self.extend(struct.pack('<I', int(data)))
            elif ntype == 'SHORT' or ntype == 'YEAR': # 2 bytes
                self.extend(struct.pack('<H', int(data)))
            elif ntype == 'TINY': # 1 bytes
                self.extend(struct.pack('<B', int(data)))

            elif ntype == 'VAR_STRING':
                self.extend(self.string_lenenc(data))

            elif ntype == 'TIMESTAMP':
                self.make_timestamp(data)

            else:
                logging.error('BinaryRowPacket:not type -> ' + ntype)
            

        return self.pack()

    def calcnull(self, row):
        # nullを格納するのに必要なバイト数を求める
        offset = 2 # 2固定
        num_fields = len(row) # 結果のフィールド数
        bitmap_bytes = int((num_fields + 7 + offset) / 8)
        # 必要な領域を確保
        nulls = [0 for i in range(bitmap_bytes)]
        for field_pos,value in enumerate(row):
            if value:
                continue

            # 格納する値の計算
            byte_pos = int((field_pos + offset) / 8)
            bit_pos  = (field_pos + offset) % 8
            nulls[byte_pos] |= 1 << bit_pos
        
        return nulls

    def make_timestamp(self, data):
        tsize = len(data)
        if tsize == 10:
            dt = datetime.datetime.strptime(data, '%Y-%m-%d')
            self.extend(struct.pack('<B', 4)) # size
            self.extend(struct.pack('<HBB', dt.year, dt.month, dt.day))

        elif tsize == 19:
            dt = datetime.datetime.strptime(data, '%Y-%m-%d %H:%M:%S')
            self.extend(struct.pack('<B', 7)) # size
            self.extend(struct.pack('<HBB', dt.year, dt.month, dt.day))
            self.extend(struct.pack('<BBB', dt.hour, dt.minute, dt.second))
            
        elif tsize >= 23:
            dt = datetime.datetime.strptime(data, '%Y-%m-%d %H:%M:%S.%f')
            self.extend(struct.pack('<B', 11)) # size
            self.extend(struct.pack('<HBB', dt.year, dt.month, dt.day))
            self.extend(struct.pack('<BBBB', dt.hour, dt.minute, dt.second, dt.microsecond))

        else:
            self.extend(struct.pack('<B', 0))
            logging.warn('Unmatch timestamp:' + data)


# PREPARE Response
class PrepareOkPacket(Packet):
    def make(self, client, num_columns, num_params):
        self.extend(struct.pack('<B', 0x00)) # ok 0x00
        self.extend(struct.pack('<I', 1)) # statement_id
        self.extend(struct.pack('<H', num_columns)) # num_columns
        self.extend(struct.pack('<H', num_params)) # num_params
        self.extend(struct.pack('<B', 0)) # reserved_1 0X00 filler

        self.extend(struct.pack('<H', 0)) # warning_count

        if client.resultset_metadata:
            self.extend(struct.pack('<B', 0)) # metadata_follows

        return self.pack()    


class EofPacket(Packet):
    def make(self):
        # eof
        self.extend(struct.pack('<B', 0xfe)) # eof 0xFE
        self.extend(struct.pack('<H', 0)) # affected_rows
        self.extend(struct.pack('<H', 2)) # SERVER_STATUS_flags_enum
        #self.extend(struct.pack('<H', 0)) # number of warnings

        return self.pack()



# ------------------------------------------------------------------
# クライアントからのハンドシェイク解析
class Client(object):
    def __init__(self, packet):
        self.parse(packet)
        self.prepare = None

    def parse(self, packet):
        # 3byte size
        packet_size, = struct.unpack('<I', packet[:3] + b'\x00')
        # 1byte sequence
        self.sequence = packet[3]
        protcol = packet[4:4+packet_size]
        
        # client_flag, max_packet_size, character_setを取得
        self.client_flag, self.max_packet_size = struct.unpack('<II', protcol[0:8])
        self.character_set = protcol[8]
        
        filler = protcol[9:9+23]
        
        self.vuser, user_len = self.read_string_nul(protcol[32:])
        # 以降、付帯情報 特に使用していないので読み捨て
        protcol = protcol[32+user_len:]

        # フラグにより有効な機能を判定
        self.deprecate_eof = False
        self.resultset_metadata = False
        self.query_attributes = False

        CLIENT_DEPRECATE_EOF = 1 << 24
        if self.client_flag & CLIENT_DEPRECATE_EOF == CLIENT_DEPRECATE_EOF:
            self.deprecate_eof = True

        CLIENT_OPTIONAL_RESULTSET_METADATA = 1 << 25
        if self.client_flag & CLIENT_OPTIONAL_RESULTSET_METADATA == CLIENT_OPTIONAL_RESULTSET_METADATA:
            self.resultset_metadata = True

        CLIENT_QUERY_ATTRIBUTES = 1 << 27
        if self.client_flag & CLIENT_QUERY_ATTRIBUTES == CLIENT_QUERY_ATTRIBUTES:
            self.query_attributes = True


    def read_string_nul(self, value):
        nul_index = value.find(0x00)
        return value[:nul_index].decode('utf-8'), nul_index+1

    
    def set_setting(self, setting):
        for k, v in setting.items():
            setattr(self, k, v)


# クライアントからのリクエスト解析
class Request(object):
    def __init__(self, packet, client):

        if not len(packet):
            logging.error('<-- Empty Request')
            self.sequence = 0
            self.command = COM_QUIT
            return

        # 3byte size
        packet_size, = struct.unpack('<I', packet[:3] + b'\x00')
        # 1byte sequence
        self.sequence = packet[3]
        protcol = packet[4:4+packet_size]
        
        # 1byte command
        self.command = protcol[0]

        # -- Text Protocol
        if self.command == COM_QUERY: # COM_QUERY
            logging.info('<-- COM_QUERY')

            shift = 0
            # com_queryにアトリビュートを含む設定なら解析
            if client.query_attributes:
                self.parameter_count = protcol[1]
                self.parameter_set_count = protcol[2]
                shift = 2

            self.query = protcol[1+shift:].decode('utf-8').strip()
            logging.info(self.query)

        # -- Prepared Statements
        elif self.command == COM_STMT_PREPARE: # COM_STMT_PREPARE
            logging.info('<-- COM_STMT_PREPARE')
            self.query = protcol[1:].decode('utf-8').strip()
            logging.info(self.query)

        elif self.command == COM_STMT_EXECUTE: # COM_STMT_EXECUTE
            logging.info('<-- COM_STMT_EXECUT')
            protcol = protcol[1:]
            statement_id, self.flags, iteration_count = struct.unpack('<IBI', protcol[0:9])
            protcol = protcol[9:]
            # ここで条件によってはparameter_countが入る
            # https://dev.mysql.com/doc/dev/mysql-server/9.3.0/page_protocol_com_stmt_execute.html
            # fillerを読み飛ばし
            protcol = protcol[1:]
            new_params_bind_flag = protcol[0]
            protcol = protcol[1:]
            self.binds = []
            bind_types = []
            
            # 最初にデータ型がnum_params分格納
            for i in range(client.prepare['num_params']):
                if not len(protcol):
                    logging.error('COM_STMT_EXECUTE binds data type is short.')
                    break

                ftype, = struct.unpack('<H', protcol[0:2])
                bind_types.append(ftype)
                protcol = protcol[2:]

            # 続いて値がnum_params分格納
            for i in range(client.prepare['num_params']):
                if not len(protcol):
                    logging.error('COM_STMT_EXECUTE binds data value is short.')
                    break

                value, size = self.string_lenenc(protcol)
                protcol = protcol[size:]
                self.binds.append(value)


        
        elif self.command == COM_STMT_CLOSE: # COM_STMT_CLOSE
            logging.info('<-- COM_STMT_EXECUT')

        
        # -- Utility Commands
        elif self.command == COM_QUIT: # COM_QUIT
            logging.info('<-- COM_QUIT')

        elif self.command == COM_PING: # COM_PING
            logging.info('<-- COM_PING')

        else:
            logging.error('<-- UNKNOWN')
            logging.error(protcol)
            

    def string_lenenc(self, data):
        if not len(data):
            return ('', 0)

        # @todo size parse
        size = 0
        value = ''
        if data[0] < 0xfb:
            size = data[0] + 1
            value = data[1:size].decode('utf-8')

        return (value, size)


# ------------------------------------------------------------------
def main():
    HOST, PORT = '0.0.0.0', 13306

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)s %(message)s"
    )

    with MySQLHTServer((HOST, PORT), MySQLHTHandler) as server:
        try:
            logging.info(f'Listen {HOST}:{PORT}.')
            server.serve_forever()
        
        except KeyboardInterrupt:
            pass
        except Exception as e:
            logging.error(e)
        
        server.server_close()
        logging.info('Close server.')


if __name__ == '__main__':
    if not os.path.exists(CONFIG_FILE_NAME):
        logging.error(f'設定ファイル{CONFIG_FILE_NAME}が見つかりません')
        exit()
    
    main()
    
