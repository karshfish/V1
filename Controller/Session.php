<?php
require_once 'DB.php';
require_once '../Model/Response.php';
try {
    $writeDB = DB::connectWriteDB();
    if (array_key_exists('sessionid', $_GET)) {
        $sessionId = $_GET['sessionid'];
        if (!is_numeric($sessionId) || $sessionId === '') {
            $response = new Response();
            $response->setSuccess(false);
            $response->setHttpStatusCode(400);
            !is_numeric($sessionID) ? $response->addMessage("Session ID must be numeric") : null;
            $sessionID === '' ? $response->addMessage("Session ID cannot be blank") : null;
            $response->send();
            exit;
        }
        if (!isset($_SERVER['HTTP_AUTHORIZATION']) || strlen($_SERVER['HTTP_AUTHORIZATION']) < 1) {
            $response = new Response();
            $response->setSuccess(false);
            $response->setHttpStatusCode(401);
            !isset($_SERVER['HTTP_AUTHORIZATION']) ? $response->addMessage("Authorization header not found") : null;
            strlen($_SERVER['HTTP_AUTHORIZATION']) < 1 ? $response->addMessage("Authorization header cannot be blank") : null;
            $response->send();
            exit;
        }
        $authorizationHeader = $_SERVER['HTTP_AUTHORIZATION'];
        if ($_SERVER['REQUEST_METHOD'] === 'DELETE') {
            try {
                $query = $writeDB->prepare('DELETE FROM tbl_sessions WHERE id = :sessionid and accessToken = :accesstoken');
                $query->bindParam(':sessionid', $sessionId, PDO::PARAM_INT);
                $query->bindParam(':accesstoken', $authorizationHeader, PDO::PARAM_STR);
                $query->execute();
                $rowCount = $query->rowCount();
                if ($rowCount === 0) {
                    $response = new Response();
                    $response->setSuccess(false);
                    $response->setHttpStatusCode(404);
                    $response->addMessage("Session not found");
                    $response->send();
                    exit;
                }

                $response = new Response();
                $response->setSuccess(true);
                $response->setHttpStatusCode(200);
                $response->addMessage("Session deleted successfully");
                $response->send();
                exit;
            } catch (PDOException $e) {
                $response = new Response();
                $response->setSuccess(false);
                $response->setHttpStatusCode(500);
                $response->addMessage("There was an issue deleting the session, please try again");
                $response->send();
                exit;
            }
        } elseif ($_SERVER['REQUEST_METHOD'] === 'PATCH') {
            if ($_SERVER['CONTENT_TYPE'] !== 'application/json') {
                $response = new Response();
                $response->setSuccess(false);
                $response->setHttpStatusCode(400);
                $response->addMessage("Content Type header not set to JSON");
                $response->send();
                exit;
            }
            sleep(1);
            $rawPatchData = file_get_contents('php://input');
            if (!$jsonData = json_decode($rawPatchData)) {
                $response = new Response();
                $response->setSuccess(false);
                $response->setHttpStatusCode(400);
                $response->addMessage("Request body is not valid JSON");
                $response->send();
                exit;
            }
            if (!isset($jsonData->accessToken) || !isset($jsonData->refreshToken)) {
                $response = new Response();
                $response->setSuccess(false);
                $response->setHttpStatusCode(400);
                (!isset($jsonData->accessToken) ? $response->addMessage("Access Token field is mandatory") : null);
                (!isset($jsonData->refreshToken) ? $response->addMessage("Refresh Token field is mandatory") : null);
                $response->send();
                exit;
            }
            if (strlen($jsonData->accessToken) < 1 || strlen($jsonData->accessToken) > 255 || strlen($jsonData->refreshToken) < 1 || strlen($jsonData->refreshToken) > 255) {
                $response = new Response();
                $response->setSuccess(false);
                $response->setHttpStatusCode(400);
                (strlen($jsonData->accessToken) < 1 ? $response->addMessage("Access Token cannot be blank") : null);
                (strlen($jsonData->accessToken) > 255 ? $response->addMessage("Access Token cannot be more than 255 characters") : null);
                (strlen($jsonData->refreshToken) < 1 ? $response->addMessage("Refresh Token cannot be blank") : null);
                (strlen($jsonData->refreshToken) > 255 ? $response->addMessage("Refresh Token cannot be more than 255 characters") : null);
                $response->send();
                exit;
            }
            try {
                $refreshToken = $jsonData->refreshToken;
                $query = $writeDB->prepare('SELECT tbl_sessions.id as sessionId, tbl_sessions.userID as userId, tbl_sessions.accessToken as accessToken, tbl_sessions.refreshToken as refreshToken, tbl_sessions.accessTokenExpiry as accessTokenExpiry, tbl_sessions.refreshTokenExpiry as refreshTokenExpiry, tbl_users.username as username, tbl_users.userActive,tbl_users.loginAttempts FROM tbl_sessions, tbl_users WHERE tbl_sessions.id = :sessionid and tbl_sessions.userId = tbl_users.id and tbl_sessions.accessToken = :accesstoken');
                $query->bindParam(':sessionid', $sessionId, PDO::PARAM_INT);
                $query->bindParam(':accesstoken', $authorizationHeader, PDO::PARAM_STR);
                $query->bindParam(':refreshtoken', $refreshToken, PDO::PARAM_STR);
                $query->execute();
                $rowCount = $query->rowCount();
                if ($rowCount === 0) {
                    $response = new Response();
                    $response->setSuccess(false);
                    $response->setHttpStatusCode(404);
                    $response->addMessage("Session not found, There wasa problem with the refresh token or access token");
                    $response->send();
                    exit;
                }
                $row = $query->fetch(PDO::FETCH_ASSOC);
                $returnedSessionId = $row['sessionId'];
                $returnedUserId = $row['userId'];
                $returnedAccessToken = $row['accessToken'];
                $returnedRefreshToken = $row['refreshToken'];
                $returnedAccessTokenExpiry = $row['accessTokenExpiry'];
                $returnedRefreshTokenExpiry = $row['refreshTokenExpiry'];
                $returnedUsername = $row['username'];
                $returnedUserActive = $row['userActive'];
                $returnedLoginAttempts = $row['loginAttempts'];
                if ($returnedUserActive !== 'Y') {
                    $response = new Response();
                    $response->setSuccess(false);
                    $response->setHttpStatusCode(401);
                    $response->addMessage("Authentication failed, account is inactive");
                    $response->send();
                    exit;
                }
                if ($returnedLoginAttempts >= 3) {
                    $response = new Response();
                    $response->setSuccess(false);
                    $response->setHttpStatusCode(401);
                    $response->addMessage("Authentication failed, account is locked");
                    $response->send();
                    exit;
                }
                if (strtotime($returnedAccessTokenExpiry) < time()) {
                    $response = new Response();
                    $response->setSuccess(false);
                    $response->setHttpStatusCode(401);
                    $response->addMessage("Access token expired, please login again");
                    $response->send();
                    exit;
                }
                if (strtotime($returnedRefreshTokenExpiry) < time()) {
                    $response = new Response();
                    $response->setSuccess(false);
                    $response->setHttpStatusCode(401);
                    $response->addMessage("Refresh token expired, please login again");
                    $response->send();
                    exit;
                }
                $accessToken = base64_encode(bin2hex(openssl_random_pseudo_bytes(24)) . time());
                $refreshToken = base64_encode(bin2hex(openssl_random_pseudo_bytes(24)) . time());
                $accessTokenExpiry = 3600;
                $refreshTokenExpiry = 1209600;
                $query = $writeDB->prepare('UPDATE tbl_sessions SET accessToken = :accesstoken, refreshToken = :refreshtoken, accessTokenExpiry = date_add(NOW(),INTERVAL :accessTokenExpirySeconds SECOND), refreshTokenExpiry = date_add(NOW(),INTERVAL :refreshTokenExpirySeconds SECOND)
                WHERE id = :sessionid and accessToken = :oldaccesstoken and refreshToken = :oldrefreshtoken and userId = :userid');
                $query->bindParam(':userid', $returnedUserId, PDO::PARAM_INT);
                $query->bindParam(':sessionid', $returnedSessionId, PDO::PARAM_INT);
                $query->bindParam(':accesstoken', $accessToken, PDO::PARAM_STR);
                $query->bindParam(':refreshtoken', $refreshToken, PDO::PARAM_STR);
                $query->bindParam(':accessTokenExpirySeconds', $accessTokenExpiry, PDO::PARAM_INT);
                $query->bindParam(':refreshTokenExpirySeconds', $refreshTokenExpiry, PDO::PARAM_INT);
                $query->bindParam(':oldaccesstoken', $returnedAccessToken, PDO::PARAM_STR);
                $query->bindParam(':oldrefreshtoken', $returnedRefreshToken, PDO::PARAM_STR);
                $query->execute();
                $rowCount = $query->rowCount();
                if ($rowCount === 0) {
                    $response = new Response();
                    $response->setSuccess(false);
                    $response->setHttpStatusCode(401);
                    $response->addMessage("Session not found, there was a problem with the refresh token or access token");
                    $response->send();
                    exit;
                }
                $returnedData = array();
                $returnedData['sessionId'] = intval($returnedSessionId);
                $returnedData['accessToken'] = $accessToken;
                $returnedData['refreshToken'] = $refreshToken;
                $returnedData['accessTokenExpiry'] = $accessTokenExpiry;
                $returnedData['refreshTokenExpiry'] = $refreshTokenExpiry;
                $response = new Response();
                $response->setSuccess(true);
                $response->setHttpStatusCode(200);
                $response->setData($returnedData);
                $response->addMessage("Session updated successfully");
                $response->send();
                exit;
            } catch (PDOException $ex) {
                $response = new Response();
                $response->setSuccess(false);
                $response->setHttpStatusCode(500);
                $response->addMessage("There was an issue updating the session, please try again");
                $response->send();
                exit;
            }
        } else {
            $response = new Response();
            $response->setSuccess(false);
            $response->setHttpStatusCode(405);
            $response->addMessage("Request methode not supported");
            $response->send();
            exit;
        }
    } elseif (empty($_GET)) {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            $response = new Response();
            $response->setSuccess(false);
            $response->setHttpStatusCode(405);
            $response->addMessage("Request Method not allowed");
            $response->send();
            exit;
        }
        sleep(1);
        if ($_SERVER['CONTENT_TYPE'] !== 'application/json') {
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
        if (!isset($jsonData->username) || !isset($jsonData->password)) {
            $response = new Response();
            $response->setSuccess(false);
            $response->setHttpStatusCode(400);
            (!isset($jsonData->username) ? $response->addMessage("username field is mandatory") : null);
            (!isset($jsonData->password) ? $response->addMessage("Password field is mandatory") : null);
            $response->send();
            exit;
        }
        if (strlen($jsonData->username) < 1 || strlen($jsonData->username) > 255 || strlen($jsonData->password) < 1 || strlen($jsonData->password) > 255) {
            $response = new Response();
            $response->setSuccess(false);
            $response->setHttpStatusCode(400);
            (strlen($jsonData->username) < 1 ? $response->addMessage("username cannot be blank") : null);
            (strlen($jsonData->username) > 255 ? $response->addMessage("username cannot be more than 255 characters") : null);
            (strlen($jsonData->password) < 1 ? $response->addMessage("Password cannot be blank") : null);
            (strlen($jsonData->password) > 255 ? $response->addMessage("Password cannot be more than 255 characters") : null);
            $response->send();
            exit;
        }
        $givenUsername = $jsonData->username;
        $givenPassword = $jsonData->password;
        try {
            $query = $writeDB->prepare('SELECT id, fullName, username, password, userActive, loginAttempts FROM tbl_users WHERE username = :username');
            $query->bindParam(':username', $givenUsername, PDO::PARAM_STR);
            $query->execute();
            $rowCount = $query->rowCount();
            if ($rowCount === 0) {
                $response = new Response();
                $response->setSuccess(false);
                $response->setHttpStatusCode(401);
                $response->addMessage("Authentication failed");
                $response->send();
                exit;
            }
            $row = $query->fetch(PDO::FETCH_ASSOC);
            $returnedUsername = $row['username'];
            $returnedPassword = $row['password'];
            $returnedUserActive = $row['userActive'];
            $returnedLoginAttempts = $row['loginAttempts'];
            $returnedId = $row['id'];
            $returnedFullName = $row['fullName'];
            if ($returnedLoginAttempts >= 3) {
                $response = new Response();
                $response->setSuccess(false);
                $response->setHttpStatusCode(401);
                $response->addMessage("Authentication failed, account is locked");
                $response->send();
                exit;
            }
            if ($returnedUserActive !== 'Y') {
                $response = new Response();
                $response->setSuccess(false);
                $response->setHttpStatusCode(401);
                $response->addMessage("Authentication failed, account is inactive");
                $response->send();
                exit;
            }
            if (!password_verify($givenPassword, $returnedPassword)) {
                $query = $writeDB->prepare('UPDATE tbl_users SET loginAttempts = loginAttempts + 1 WHERE username = :username');
                $query->bindParam(':username', $givenUsername, PDO::PARAM_STR);
                $query->execute();
                $response = new Response();
                $response->setSuccess(false);
                $response->setHttpStatusCode(401);
                $response->addMessage("Authentication failed");
                $response->send();
                exit;
            }
            $accessToken = base64_encode(bin2hex(openssl_random_pseudo_bytes(24)) . time());
            $refreshToken = base64_encode(bin2hex(openssl_random_pseudo_bytes(24)) . time());
            $accessTokenExpiry = 3600;
            $refreshTokenExpiry = 604800;
        } catch (PDOException $e) {
            $response = new Response();
            $response->setSuccess(false);
            $response->setHttpStatusCode(500);
            $response->addMessage("Ther e was an issue logging you in, please try again");
            $response->send();
            exit;
        }
        try {
            $writeDB->beginTransaction();
            $query = $writeDB->prepare('UPDATE tbl_users SET loginAttempts = 0 WHERE username = :username');
            $query->bindParam(':username', $givenUsername, PDO::PARAM_STR);
            $query->execute();
            $query = $writeDB->prepare('INSERT INTO tbl_sessions (userId, accessToken, refreshToken, accessTokenExpiry, refreshTokenExpiry) VALUES 
            (:userid, :accesstoken, :refreshtoken,
            date_add(NOW(),INTERVAL :accessTokenExpirySeconds SECOND),
            date_add(NOW(),INTERVAL :refreshTokenExpirySeconds SECOND))');
            $query->bindParam(':userid', $returnedId, PDO::PARAM_INT);
            $query->bindParam(':accesstoken', $accessToken, PDO::PARAM_STR);
            $query->bindParam(':refreshtoken', $refreshToken, PDO::PARAM_STR);
            $query->bindParam(':accessTokenExpirySeconds', $accessTokenExpiry, PDO::PARAM_INT);
            $query->bindParam(':refreshTokenExpirySeconds', $refreshTokenExpiry, PDO::PARAM_INT);

            $query->execute();
            $lastSessionId = $writeDB->lastInsertId();
            $writeDB->commit();
            $returnedData = array();
            $returnedData['sessionId'] = intval($lastSessionId);
            $returnedData['accessToken'] = $accessToken;
            $returnedData['refreshToken'] = $refreshToken;
            $returnedData['accessTokenExpiry'] = $accessTokenExpiry;
            $returnedData['refreshTokenExpiry'] = $refreshTokenExpiry;
            $response = new Response();
            $response->setSuccess(true);
            $response->setHttpStatusCode(201);
            $response->setData($returnedData);
            $response->addMessage("User logged in successfully");
            $response->send();
            exit;
        } catch (PDOException $e) {
            $writeDB->rollBack();
            $response = new Response();
            $response->setSuccess(false);
            $response->setHttpStatusCode(500);
            $response->addMessage("There was an issue logging you in, please try again");
            $response->send();
            exit;
        }
    } else {
        $response = new Response();
        $response->setSuccess(false);
        $response->setHttpStatusCode(404);
        $response->addMessage("Endpoint not found");
        $response->send();
        exit;
    }
} catch (PDOException $e) {
    error_log("Connection failed: " . $e->getMessage());
    $response = new Response();
    $response->setSuccess(false);
    $response->setHttpStatusCode(500);
    $response->addMessage("Database Connection failed: " . $e->getMessage());
    $response->send();
    exit;
}
