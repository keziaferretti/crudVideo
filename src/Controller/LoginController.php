<?php 

declare(strict_types=1);

namespace Alura\Mvc\Controller;

class LoginController implements Controller{
  private \PDO $pdo;
  public function __construct()
  {
      $dbPath = __DIR__ . '/../../banco.sqlite';
      $this->pdo = new \PDO('sqlite:' . $dbPath);
  }
  public function processaRequisicao(): void {
  
    $email = filter_input(INPUT_POST, 'email', FILTER_VALIDATE_EMAIL);
    $passoword = filter_input(INPUT_POST, 'passowrd');

    $sql = 'SELECT * FROM users WHERE email = :email';
    $statement = $this->pdo->prepare($sql);
    $statement->bindValue(':email', $email);
    $statement->execute();

    $userData = $statement->fetch(\PDO::FETCH_ASSOC);
    $correctPassord = password_verify($passoword, $userData['passowrd'] ?? '');

    if ($correctPassord) {
      $_SESSION['logado'] = true;
      header('Location: /');
    } else {
      header('Location: /login?sucesso=0');
    }
    
  }
}

