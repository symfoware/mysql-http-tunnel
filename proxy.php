<?php

function send_response($response) {
    header('Content-Type', 'application/octet-stream');
    $json = json_encode($response);
    $zip = gzdeflate($json, -1, ZLIB_ENCODING_DEFLATE);
    echo($zip);
    exit(0);
}

// json形式だとwafに止められるパターンがある模様 jsonをzip圧縮したデータを送信
$content = file_get_contents('php://input');
$decode = gzuncompress($content);
$request = json_decode($decode, true);


$dsn = "mysql:host={$request['host']};dbname={$request['database']};charset={$request['charset']}";
$user = $request['user'];
$password = $request['password'];
$query = $request['query'];

$cols = [];
$rows = [];
$pdo = null;
$affected = 0;

try {
    $pdo = new PDO($dsn, $user, $password);
} catch (PDOException $e) {
    list($state, $code, $message) = $e->errorInfo;
    send_response([
        'state' => $state,
        'code' => $code,
        'message' => $message,
    ]);
}

try {
    // SQL実行
    $stmt = $pdo->query($query);

    // カラム数取得
    $columnCount = $stmt->columnCount();
    for($column = 0; $column < $columnCount; $column++) {
        // カラムのメタ情報を取得
        $cols[] = $stmt->getColumnMeta($column);
    }

    // 行情報取得
    while($row = $stmt->fetch(PDO::FETCH_NUM)) {
        $rows[] = $row;
    }
    
    // 影響を受けた行数
    $affected = $stmt->rowCount();



} catch (PDOException $e) {
    list($state, $code, $message) = $e->errorInfo;
    send_response([
        'state' => $state,
        'code' => $code,
        'message' => $message,
    ]);
}

$response = [
    'state' => 0,
    'cols' => $cols,
    'rows' => $rows,
    'last_insert_id' => intval($pdo->lastInsertId()),
    'affected' => intval($affected)
];
send_response($response);
