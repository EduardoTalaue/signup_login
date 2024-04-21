

<?php

if (empty($_POST["name"])) {
    die("Name is required");
}

if ( ! filter_var($_POST["email"], FILTER_VALIDATE_EMAIL)) {
    die("Valid email is required");
}

if (strlen($_POST["password"]) < 8) {
    die("Password must be at least 8 characters");
}

if ( ! preg_match("/[a-z]/i", $_POST["password"])) {
    die("Password must contain at least one letter");
}

if ( ! preg_match("/[0-9]/", $_POST["password"])) {
    die("Password must contain at least one number");
}

if ($_POST["password"] !== $_POST["password_confirmation"]) {
    die("Passwords must match");
}

$password_hash = password_hash($_POST["password"], PASSWORD_DEFAULT);

$mysqli = require __DIR__ . "/database.php";

$sql = "INSERT INTO user (name, email, password_hash)
        VALUES (?, ?, ?)";
        
$stmt = $mysqli->stmt_init();

if ( ! $stmt->prepare($sql)) {
    die("SQL error: " . $mysqli->error);
}

$stmt->bind_param("sss",
                  $_POST["name"],
                  $_POST["email"],
                  $password_hash);
                  
if ($stmt->execute()) {

    header("Location: signup-success.html");
    exit;
    
} else {
    
    if ($mysqli->errno === 1062) {
        die("email already taken");
    } else {
        die($mysqli->error . " " . $mysqli->errno);
    }
}


$is_invalid = false;

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    
    $mysqli = require __DIR__ . "/database.php";
    
    $sql = sprintf("SELECT * FROM user
                    WHERE email = '%s'",
                   $mysqli->real_escape_string($_POST["email"]));
    
    $result = $mysqli->query($sql);
    
    $user = $result->fetch_assoc();
    
    if ($user) {
        
        if (password_verify($_POST["password"], $user["password_hash"])) {
            
            session_start();
            
            session_regenerate_id();
            
            $_SESSION["user_id"] = $user["id"];
            
            header("Location: index.php");
            exit;
        }
    }
    
    $is_invalid = true;
}

?>
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <meta charset="UTF-8">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/water.css@2/out/water.css">
</head>
<style>
     body {
    margin: 0; 
    display: flex;
    flex-direction: column; 
    align-items: center; 
    padding-top: 20px;
    background-image: url('image/jk.jpg');
    background-size: cover;
    background-repeat: no-repeat; 
    background-position: center; 
    background-attachment: fixed; 
    opacity: 0.8; 
     }
        form {
            margin-top: 100px;
            width: 100%; 
            max-width: 330px; 
            padding: 20px; 
            background-color: transparent;
            border-radius: 8px; 
            box-shadow: 0px 2px 10px rgba(0, 0, 0, 0.1); 
            
        }

    
        input {
            margin-bottom: 10px;
            width: 330px; 
            box-sizing: border-box; 
        }
        h1 {
 
            color: red; 
            text-align: center; 
        
        }
        button{
            background-color: red;
            margin-top: 10px;
            margin-left:110px;
            margin-right: auto;
        }
</style>
<body>
    
   
    
    <?php if ($is_invalid): ?>
        <em>Invalid login</em>
    <?php endif; ?>
    
    <form method="post" id="login">
    <h1>Login</h1>
        <input type="email" name="email" id="email" placeholder="Email"
               value="<?= htmlspecialchars($_POST["email"] ?? "") ?>">
        
        <input type="password" name="password" id="password" placeholder="Password">
        
        <button>Log in</button>
        <p>Register Here!<a href = "login.php">Register</a></p>
    </form>
</body>
</html>
