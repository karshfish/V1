<?php
require_once('../Model/Response.php');
require_once('DB.php');
try {
    $writeDB = DB::connectWriteDB();
} catch (PDOException $e) {
    error_log("Connection error - " . $e, 0);
    $response = new Response();
    $response->setSuccess(false);
    $response->setHttpStatusCode(500);
    $response->addMessage("Connection error");
    $response->send();
    exit;
}
if (empty($_GET)) {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        $response = new Response();
        $response->setSuccess(false);
        $response->setHttpStatusCode(405);
        $response->addMessage("Request Method not allowed");
        $response->send();
        exit;
    }
    sleep(1);
    if (!isset($_SERVER['CONTENT_TYPE']) || $_SERVER['CONTENT_TYPE'] !== 'application/json') {
        $response = new Response();
        $response->setSuccess(false);
        $response->setHttpStatusCode(400);
        $response->addMessage("Content Type header not set to JSON");
        $response->send();
        exit;
    }
    $rawPostData = file_get_contents('php://input');
    if (!$jsonData = json_decode($rawPostData)) {
        $response = new Response();
        $response->setSuccess(false);
        $response->setHttpStatusCode(400);
        $response->addMessage("Request body is not valid JSON");
        $response->send();
        exit;
    }
    if (!isset($jsonData->username) || !isset($jsonData->password) || !isset($jsonData->fullName)) {
        $response = new Response();
        $response->setSuccess(false);
        $response->setHttpStatusCode(400);
        (!isset($jsonData->username) ? $response->addMessage("username field is mandatory") : null);
        (!isset($jsonData->password) ? $response->addMessage("Password field is mandatory") : null);
        (!isset($jsonData->fullName) ? $response->addMessage("Full Name field is mandatory") : null);
        $response->send();
        exit;
    }
    if (strlen($jsonData->username) < 1 || strlen($jsonData->username) > 255 || strlen($jsonData->password) < 1 || strlen($jsonData->password) > 255 || strlen($jsonData->fullName) < 1 || strlen($jsonData->fullName) > 255) {
        $response = new Response();
        $response->setSuccess(false);
        $response->setHttpStatusCode(400);
        (strlen($jsonData->username) < 1 ? $response->addMessage("username cannot be blank") : null);
        (strlen($jsonData->username) > 255 ? $response->addMessage("username cannot be more than 255 characters") : null);
        (strlen($jsonData->password) < 1 ? $response->addMessage("Password cannot be blank") : null);
        (strlen($jsonData->password) > 255 ? $response->addMessage("Password cannot be more than 255 characters") : null);
        (strlen($jsonData->fullName) < 1 ? $response->addMessage("Full Name cannot be blank") : null);
        (strlen($jsonData->fullName) > 255 ? $response->addMessage("Full Name cannot be more than 255 characters") : null);
        $response->send();
        exit;
    }
    $fullName = trim($jsonData->fullName);
    $givenUsername = trim($jsonData->username);
    $givenPassword = $jsonData->password;
    try {
        $query = $writeDB->prepare('SELECT id, fullName, username, password, userActive, loginAttempts FROM tbl_users WHERE username = :username');
        $query->bindParam(':username', $givenUsername, PDO::PARAM_STR);
        $query->execute();
        $rowCount = $query->rowCount();
        if ($rowCount !== 0) {
            $response = new Response();
            $response->setSuccess(false);
            $response->setHttpStatusCode(409);
            $response->addMessage("Username already exists");
            $response->send();
            exit;
        }
        $hashedPassword = password_hash($givenPassword, PASSWORD_DEFAULT);
        $query = $writeDB->prepare('INSERT INTO tbl_users (fullName, username, password, userActive, loginAttempts) VALUES (:fullName, :username, :password, 1, 0)');
        $query->bindParam(':fullName', $fullName, PDO::PARAM_STR);
        $query->bindParam(':username', $givenUsername, PDO::PARAM_STR);
        $query->bindParam(':password', $hashedPassword, PDO::PARAM_STR);
        $query->execute();
        $lastUserID = $writeDB->lastInsertId();
        $rowCount = $query->rowCount();
        if ($rowCount === 0) {
            $response = new Response();
            $response->setSuccess(false);
            $response->setHttpStatusCode(500);
            $response->addMessage("Failed to create user account");
            $response->send();
            exit;
        }
        $query = $writeDB->prepare('SELECT id, fullName, username, userActive FROM tbl_users WHERE id = :id');
        $query->bindParam(':id', $lastUserID, PDO::PARAM_INT);
        $query->execute();
        $rowCount = $query->rowCount();
        if ($rowCount === 0) {
            $response = new Response();
            $response->setSuccess(false);
            $response->setHttpStatusCode(500);
            $response->addMessage("Failed to retrieve user account");
            $response->send();
            exit;
        }
        $row = $query->fetch(PDO::FETCH_ASSOC);
        $returnedId = $row['id'];
        $returnedFullName = $row['fullName'];
        $returnedUsername = $row['username'];
        $returnedUserActive = $row['userActive'];
        $response = new Response();
        $response->setSuccess(true);
        $response->setHttpStatusCode(201);
        $response->addMessage("User account created successfully");
        $response->setData(array('id' => $returnedId, 'fullName' => $returnedFullName, 'username' => $returnedUsername, 'userActive' => $returnedUserActive));
        $response->send();
        exit;
    } catch (PDOException $e) {
        error_log("Database query error - " . $e, 0);
        $response = new Response();
        $response->setSuccess(false);
        $response->setHttpStatusCode(500);
        $response->addMessage("Database query error");
        $response->send();
        exit;
    }
}
