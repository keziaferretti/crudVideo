<?php 


declare(strict_types=1);

$dbPath = __DIR__ . '/banco.sqlite';
$pdo = new PDO("sqlite:$dbPath");

$email = $argv[1];
$passowrd = $argv[2];
$hash = password_hash($passowrd, PASSWORD_ARGON2ID);

$sql = 'INSERT INTO users (email, passowrd) VALUES (?, ?)';
$stratement = $pdo->prepare($sql);
$stratement->bindValue(1, $email);
$stratement->bindValue(2, $hash);
$stratement->execute();


