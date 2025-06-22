# mysql-http-tunnel

MySQLプロコルを応答する踏み台サーバー  

SQL実行要求を受け取ると、設定ファイルに記載したwebサーバー上のPHPプログラムを実行しSQLを実行  
実行結果を受け取り、MySQLプロトコルに変換して応答します  

http(s) + JSONをプロトコルを挟みますが、このサーバーへに対する接続はMySQLプロトコルになります  

[MySQL Client] --(MySQL Protocol)-- [mysql-http-tunnel] --(http(s) + JSON)-- [PHP + PDO] --(MySQL Protocol)-- [MySQL Server]

特定のwebサーバーからのみアクセスを許可しているMySQLサーバーに対し、MySQL Clientや使い慣れたMySQL管理ツールでローカル端末からアクセスできるようになります  
webサーバーにssh接続できない、ssh接続できるがポートフォワードが許可されておらずssh tunnelが使用できない場合に有用です  

## 設定ファイルとサーバーの起動

proxy.phpをwebサーバーで公開されているディレクトリに保存します  

default.cfg.sampleをdefault.cfgにリネーム  
データベースに接続するための情報を記載します  
セクション名がこのサーバーに接続する際のユーザー名になります  

・default.cfg

 ```text
[仮想ユーザー名]
endpoint = proxy.phpのURL
host = 接続するデータベースホスト
database = データベース名
charset = charset
user = 接続ユーザー名
password = 接続パスワード
```

・例

 ```text
[virtual_user]
endpoint = http://192.168.11.200/proxy.php
host = localhost
database = sample
charset = utf8mb4
user = admin
password = P@ssw0rd
```

設定ファイルdefault.cfgが準備できたらサーバーを起動します

```code
$ python server.py
2025-06-21 16:54:31,937 INFO Listen localhost:13306
```

サーバー起動後、ポート13306をリッスンします  
mysql.connector等、MySQLクライアントからポート13306に対してdefault.cfgで設定したセクション名をユーザー名として接続します  
パスワードは使用しません  

```py
import mysql.connector

con = mysql.connector.connect(
    user='virtual_user',
    #password=None,
    host='localhost',
    port=13306,
    #database=None
)

cur = con.cursor(dictionary=True)
query = 'show variables'

cur.execute(query)
for row in cur.fetchall():
    print(row)

con.close()
```

## 対応しているコマンド

SQL実行に必要な最低限のコマンドのみ対応しています  

- COM_QUERY
- COM_PING
- COM_QUIT

## 既知の問題

HeidiSQLからデータのあるテーブルのバックアップを行うとエラーで終了する  

## MySQL Protocol

開発時に参照したドキュメント  

### Connection Phase

ハンドシェイクを行う際のサーバーからの応答とクライアントからのリクエスト  
[Connection Phase](https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase.html)  
[Protocol::HandshakeV10](https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v10.html)  
[Protocol::HandshakeResponse41](https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_response.html)  

### Command Phase

接続確立後、SQLの実行要求や応答を行う際のプロトコル  
[Command Phase](https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_command_phase.html)  

#### クライアントからの要求

[COM_QUERY](https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query.html)  
[COM_PING](https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_ping.html)  
[COM_QUIT](https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_quit.html)  

#### サーバーからの応答

[OK_Packet](https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_ok_packet.html)  
[ERR_Packet](https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_err_packet.html)  
[COM_QUERY Response](https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query_response.html)  
[Text Resultset](https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query_response_text_resultset.html)  
[Protocol::ColumnDefinition41](https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query_response_text_resultset_column_definition.html)  
[Text Resultset Row](https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query_response_text_resultset_row.html)  

#### 定数等

[enum_field_types](https://dev.mysql.com/doc/dev/mysql-server/latest/field__types_8h.html#a69e798807026a0f7e12b1d6c72374854)  
[Column Definition Flags](https://dev.mysql.com/doc/dev/mysql-server/latest/group__group__cs__column__definition__flags.html)  
[field_types.h File Reference](https://dev.mysql.com/doc/dev/mysql-server/latest/field__types_8h.html)  
