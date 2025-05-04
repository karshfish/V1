<?php
include_once '../Model/Task.php';
include_once '../Model/Response.php';
include_once 'DB.php';
try {
    $writeDB = DB::connectWriteDB();
    $readDB = DB::connectReadDB();
} catch (PDOException $ex) {
    error_log("Connection error - " . $ex, 0);
    $response = new Response();
    $response->setHttpStatusCode(500);
    $response->setSuccess(false);
    $response->addMessage("Database connection error");
    $response->send();
    exit;
}
//Creating the authentication process
//first checking the authentication header
if (!isset($_SERVER['HTTP_AUTHORIZATION']) || strlen($_SERVER['HTTP_AUTHORIZATION']) < 1) {
    $response = new Response;
    $response->setHttpStatusCode(401);
    $response->setSuccess(false);
    (!isset($_SERVER['HTTP_AUTHORIZATION']) ? $response->addMessage('Access token missing from the header') : Null);
    (strlen($_SERVER['HTTP_AUTHORIZATION']) < 1 ? $response->addMessage('Access token cannot be empty') : Null);
    $response->send();
    exit;
}
//perform a query to identify the session user and the user ID
try {
    $accessToken = $_SERVER['HTTP_AUTHORIZATION'];
    $query = $writeDB->prepare('SELECT accessTokenExpiry, userId, userActive, loginAttempts
     FROM tbl_users, tbl_sessions
     WHERE tbl_sessions.userId = tbl_users.Id AND accessToken=:accessToken');
    $query->bindParam(':accessToken', $accessToken, PDO::PARAM_STR);
    $query->execute();
    $rowCount = $query->rowCount();
    if ($rowCount === 0) {
        $response = new Response;
        $response->setHttpStatusCode(401);
        $response->setSuccess(false);
        $response->addMessage('Invalid access token');
        $response->send();
        exit;
    }

    $row = $query->fetch(PDO::FETCH_ASSOC);
    $returned_userId = $row['userId'];
    $returned_accessTokenExpiry = $row['accessTokenExpiry'];
    $returned_userActive = $row['userActive'];
    $returned_loginAttempts = $row['loginAttempts'];
    if ($returned_loginAttempts > 3) {
        $response = new Response;
        $response->setHttpStatusCode(401);
        $response->setSuccess(false);
        $response->addMessage('User is currently locked out');
        $response->send();
        exit;
    }
    if ($returned_userActive !== 'Y') {
        $response = new Response;
        $response->setHttpStatusCode(401);
        $response->setSuccess(false);
        $response->addMessage('User account is not active');
        $response->send();
        exit;
    }
    if (strtotime($returned_accessTokenExpiry) < time()) {
        $response = new Response;
        $response->setHttpStatusCode(401);
        $response->setSuccess(false);
        $response->addMessage('Access token is expired. Login again');
        $response->send();
        exit;
    }
} catch (PDOException $ex) {
    $response = new Response;
    $response->setHttpStatusCode(500);
    $response->setSuccess(false);
    $response->addMessage('Query error: ' . $ex->getMessage());
    $response->send();
    exit;
}


//end if authentication process
if (array_key_exists('taskid', $_GET)) {
    $taskid = $_GET['taskid'];
    if ($taskid == '' || !is_numeric($taskid)) {
        $response = new Response();
        $response->setHttpStatusCode(400);
        $response->setSuccess(false);
        $response->addMessage("Task ID cannot be blank or must be numeric");
        $response->send();
        exit;
    }

    if ($_SERVER['REQUEST_METHOD'] == 'GET') {
        try {
            $query = $readDB->prepare('SELECT id, title, description, DATE_FORMAT(deadline, "%d/%m/%Y %H:%i") as deadline, completed FROM tbl_tasks WHERE id = :taskid');
            $query->bindParam(':taskid', $taskid, PDO::PARAM_INT);
            $query->execute();
            $rowCount = $query->rowCount();
            if ($rowCount === 0) {
                $response = new Response();
                $response->setHttpStatusCode(404);
                $response->setSuccess(false);
                $response->addMessage("Task not found");
                $response->send();
                exit;
            }
            while ($row = $query->fetch(PDO::FETCH_ASSOC)) {
                $task = new Task($row['id'], $row['title'], $row['description'], $row['deadline'], $row['completed']);
                $taskArray[] = $task->returnTaskAsArray();
            }
            $returnData = array();
            $returnData['rows_returned'] = $rowCount;
            $returnData['tasks'] = $taskArray;
            $response = new Response();
            $response->setHttpStatusCode(200);
            $response->setSuccess(true);
            $response->toCache(true);
            $response->setData($returnData);
            $response->send();
            exit;
        } catch (TaskException $ex) {
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage($ex->getMessage());
            $response->send();
            exit;
        } catch (PDOException $ex) {
            error_log("Database query error - " . $ex, 0);
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage("Failed to get task");
            $response->send();
            exit;
        }
    } elseif ($_SERVER['REQUEST_METHOD'] === 'DELETE') {
        try {
            $query = $writeDB->prepare('DELETE FROM tbl_tasks WHERE id = :taskid');
            $query->bindParam(':taskid', $taskid, PDO::PARAM_INT);
            $query->execute();
            $rowCount = $query->rowCount();
            if ($rowCount === 0) {
                $response = new Response();
                $response->setHttpStatusCode(404);
                $response->setSuccess(false);
                $response->addMessage("Task not found");
                $response->send();
                exit;
            }
            $response = new Response();
            $response->setHttpStatusCode(200);
            $response->setSuccess(true);
            $response->addMessage("Task deleted");
            $response->send();
            exit;
        } catch (PDOException $ex) {
            error_log("Database query error - " . $ex, 0);
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage("Failed to delete task");
            $response->send();
            exit;
        }
    } else if ($_SERVER['REQUEST_METHOD'] == 'PATCH') {
        try {
            if ($_SERVER['CONTENT_TYPE'] !== 'application/json') {
                $response = new Response();
                $response->setHttpStatusCode(400);
                $response->setSuccess(false);
                $response->addMessage("Content Type header not set to JSON");
                $response->send();
                exit;
            }
            $rawPatchData = file_get_contents('php://input');
            if (!$jsonData = json_decode($rawPatchData)) {
                $response = new Response();
                $response->setHttpStatusCode(400);
                $response->setSuccess(false);
                $response->addMessage("Request body is not valid JSON");
                $response->send();
                exit;
            }
            if (isset($jsonData->title) && strlen($jsonData->title) < 1) {
                $response = new Response();
                $response->setHttpStatusCode(400);
                $response->setSuccess(false);
                $response->addMessage("Title cannot be blank");
                $response->send();
                exit;
            }
            if (isset($jsonData->completed) && ($jsonData->completed != 'Y' && $jsonData->completed != 'N')) {
                $response = new Response();
                $response->setHttpStatusCode(400);
                $response->setSuccess(false);
                $response->addMessage("Completed must be Y or N");
                $response->send();
                exit;
            }
            if (isset($jsonData->deadline)) {
                if (strlen($jsonData->deadline) < 16 || DateTime::createFromFormat('d/m/Y H:i', $jsonData->deadline) === false) {
                    $response = new Response();
                    $response->setHttpStatusCode(400);
                    $response->setSuccess(false);
                    $response->addMessage("Deadline must be in the format dd/mm/yyyy hh:mm and cannot be blank");
                    $response->send();
                    exit;
                }
            }
            // Create an array of fields to update
            // Check for each field and add it to the array if it exists
            // Then create a dynamic query based on the fields present in the array
            // Bind the parameters and execute the query

            // Initialize an empty array to hold the fields to update
            $fieldsToUpdate = array();

            // Check for each field and add it to the array if it
            // exists   
            if (isset($jsonData->title)) {
                $fieldsToUpdate['title'] = $jsonData->title;
            }
            if (isset($jsonData->description)) {
                $fieldsToUpdate['description'] = $jsonData->description;
            }
            if (isset($jsonData->deadline)) {
                $fieldsToUpdate['deadline'] = $jsonData->deadline;
            }
            if (isset($jsonData->completed)) {
                $fieldsToUpdate['completed'] = $jsonData->completed;
            }
            // Check if there are any fields to update
            if (empty($fieldsToUpdate)) {
                $response = new Response();
                $response->setHttpStatusCode(400);
                $response->setSuccess(false);
                $response->addMessage("No fields provided for update");
                $response->send();
                exit;
            }
            // Create a dynamic query based on the fields present in the array
            $queryFields = array();
            foreach ($fieldsToUpdate as $field => $value) {
                if ($field == 'deadline') {
                    $queryFields[] = "$field = STR_TO_DATE(:$field, '%d/%m/%Y %H:%i')";
                } else {
                    $queryFields[] = "$field = :$field";
                }
                // $queryFields[] = "$field = :$field";
            }
            $queryString = implode(", ", $queryFields);
            // Prepare the SQL statement
            // Use a prepared statement to prevent SQL injection
            $query = $writeDB->prepare("UPDATE tbl_tasks SET $queryString WHERE id = :taskid");
            // Bind the parameters
            foreach ($fieldsToUpdate as $field => $value) {
                if ($field == 'deadline') {
                    echo $value;
                    $query->bindParam(":$field", $fieldsToUpdate[$field], PDO::PARAM_STR);
                } else {
                    $query->bindParam(":$field", $fieldsToUpdate[$field], PDO::PARAM_STR);
                }
            }
            // Bind the task ID parameter
            $query->bindParam(':taskid', $taskid, PDO::PARAM_INT);
            $query->execute();
            $rowCount = $query->rowCount();
            if ($rowCount === 0) {
                $response = new Response();
                $response->setHttpStatusCode(404);
                $response->setSuccess(false);
                $response->addMessage("Task not found or no changes made");
                $response->send();
                exit;
            }
            $query = $writeDB->prepare('SELECT id, title, description, DATE_FORMAT(deadline, "%d/%m/%Y %H:%i") as deadline, completed FROM tbl_tasks WHERE id = :taskid');
            $query->bindParam(':taskid', $taskid, PDO::PARAM_INT);
            $query->execute();
            $rowCount = $query->rowCount();
            if ($rowCount === 0) {
                $response = new Response();
                $response->setHttpStatusCode(500);
                $response->setSuccess(false);
                $response->addMessage("Failed to retrieve task after update");
                $response->send();
                exit;
            }
            $taskArray = array();
            while ($row = $query->fetch(PDO::FETCH_ASSOC)) {
                $task = new Task($row['id'], $row['title'], $row['description'], $row['deadline'], $row['completed']);
                $taskArray[] = $task->returnTaskAsArray();
            }
            $returnData = array();
            $returnData['rows_returned'] = $rowCount;
            $returnData['tasks'] = $taskArray;
            $response = new Response();
            $response->setHttpStatusCode(200);
            $response->setSuccess(true);
            $response->addMessage("Task updated successfully");
            $response->setData($returnData);
            $response->send();
            exit;
        } catch (TaskException $ex) {
            $response = new Response();
            $response->setHttpStatusCode(400);
            $response->setSuccess(false);
            $response->addMessage($ex->getMessage());
            $response->send();
            exit;
        } catch (PDOException $ex) {
            error_log("Database query error - " . $ex, 0);
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage("Failed to update task");
            $response->send();
            exit;
        }
    }
} elseif (array_key_exists('completed', $_GET)) {
    $completed = $_GET['completed'];
    if ($completed !== 'Y' && $completed !== 'N') {
        $response = new Response();
        $response->setHttpStatusCode(400);
        $response->setSuccess(false);
        $response->addMessage("Completed filter must be Y or N");
        $response->send();
        exit;
    }
    if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        try {
            $query = $readDB->prepare('SELECT id, title, description, DATE_FORMAT(deadline, "%d/%m/%Y %H:%i") as deadline, completed FROM tbl_tasks WHERE completed = :completed');
            $query->bindParam(':completed', $completed, PDO::PARAM_STR);
            $query->execute();
            $rowCount = $query->rowCount();
            $taskArray = array();
            while ($row = $query->fetch(PDO::FETCH_ASSOC)) {
                $task = new Task($row['id'], $row['title'], $row['description'], $row['deadline'], $row['completed']);
                $taskArray[] = $task->returnTaskAsArray();
            }
            $returnData = array();
            $returnData['rows_returned'] = $rowCount;
            $returnData['tasks'] = $taskArray;
            $response = new Response();
            $response->setHttpStatusCode(200);
            $response->setSuccess(true);
            $response->toCache(true);
            $response->setData($returnData);
            $response->send();
            exit;
        } catch (TaskException $ex) {
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage($ex->getMessage());
            $response->send();
            exit;
        } catch (PDOException $ex) {
            error_log("Database query error - " . $ex, 0);
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage("Failed to get tasks");
            $response->send();
            exit;
        }
    }
} elseif (array_key_exists('page', $_GET)) {
    if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        $page = $_GET['page'];
        if ($page == '' || !is_numeric($page)) {
            $response = new Response();
            $response->setHttpStatusCode(400);
            $response->setSuccess(false);
            $response->addMessage("Page number cannot be blank and must be numeric");
            $response->send();
            exit;
        }
        $limitPerPage = 20;
        try {
            $query = $readDB->prepare('SELECT COUNT(id) as totalNoOfTasks FROM tbl_tasks');
            $query->execute();
            $row = $query->fetch(PDO::FETCH_ASSOC);
            $tasksCount = intval($row['totalNoOfTasks']);
            $numOfPages = ceil($tasksCount / $limitPerPage);
            if ($numOfPages == 0) {
                $numOfPages = 1;
            }
            if ($page > $numOfPages || $page == 0) {
                $response = new Response();
                $response->setHttpStatusCode(404);
                $response->setSuccess(false);
                $response->addMessage("Page not found");
                $response->send();
                exit;
            }
            $offset = ($page == 1 ? 0 : ($limitPerPage * ($page - 1)));
            $query = $readDB->prepare('SELECT id, title, description, DATE_FORMAT(deadline, "%d/%m/%Y %H:%i") as deadline, completed FROM tbl_tasks LIMIT :pglimit OFFSET :offset');
            $query->bindParam(':pglimit', $limitPerPage, PDO::PARAM_INT);
            $query->bindParam(':offset', $offset, PDO::PARAM_INT);
            $query->execute();
            $rowCount = $query->rowCount();
            $taskArray = array();
            while ($row = $query->fetch(PDO::FETCH_ASSOC)) {
                $task = new Task($row['id'], $row['title'], $row['description'], $row['deadline'], $row['completed']);
                $taskArray[] = $task->returnTaskAsArray();
            }
            $returnData = array();
            $returnData['rows_returned'] = $rowCount;
            $returnData['total_rows'] = $tasksCount;
            $returnData['total_pages'] = $numOfPages;
            $returnData['current_page'] = $page;
            $returnData['tasks'] = $taskArray;
            $response = new Response();
            $response->setHttpStatusCode(200);
            $response->setSuccess(true);
            $response->toCache(true);
            $response->setData($returnData);
            $response->send();
            exit;
        } catch (TaskException $ex) {
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage($ex->getMessage());
            $response->send();
            exit;
        } catch (PDOException $ex) {
            error_log("Database query error - " . $ex, 0);
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage("Failed to get tasks");
            $response->send();
            exit;
        }
    }
} elseif (empty($_GET)) {
    if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        try {
            $query = $readDB->prepare('SELECT id, title, description, DATE_FORMAT(deadline, "%d/%m/%Y %H:%i") as deadline, completed FROM tbl_tasks');
            $query->execute();
            $rowCount = $query->rowCount();
            $taskArray = array();
            while ($row = $query->fetch(PDO::FETCH_ASSOC)) {
                $task = new Task($row['id'], $row['title'], $row['description'], $row['deadline'], $row['completed']);
                $taskArray[] = $task->returnTaskAsArray();
            }
            $returnData = array();
            $returnData['rows_returned'] = $rowCount;
            $returnData['tasks'] = $taskArray;
            $response = new Response();
            $response->setHttpStatusCode(200);
            $response->setSuccess(true);
            $response->toCache(true);
            $response->setData($returnData);
            $response->send();
            exit;
        } catch (TaskException $ex) {
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage($ex->getMessage());
            $response->send();
            exit;
        } catch (PDOException $ex) {
            error_log("Database query error - " . $ex, 0);
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage("Failed to get tasks");
            $response->send();
            exit;
        }
    }
    if ($_SERVER["REQUEST_METHOD"] === 'POST') {
        try {
            if ($_SERVER['CONTENT_TYPE'] !== 'application/json') {
                $response = new Response();
                $response->setHttpStatusCode(400);
                $response->setSuccess(false);
                $response->addMessage("Content Type header not set to JSON");
                $response->send();
                exit;
            }
            $rawPostData = file_get_contents('php://input');
            if (!$jsonData = json_decode($rawPostData)) {
                $response = new Response();
                $response->setHttpStatusCode(400);
                $response->setSuccess(false);
                $response->addMessage("Request body is not valid JSON");
                $response->send();
                exit;
            }
            if (!isset($jsonData->title) || !isset($jsonData->completed)) {
                $response = new Response();
                $response->setHttpStatusCode(400);
                $response->setSuccess(false);
                (!isset($jsonData->title) ? $response->addMessage("Title field is mandatory and must be provided") : false);
                (!isset($jsonData->completed) ? $response->addMessage("Completed field is mandatory and must be provided") : false);
                $response->send();
                exit;
            }
            $newTask = new Task(null, $jsonData->title, (isset($jsonData->description) ? $jsonData->description : null), (isset($jsonData->deadline) ? $jsonData->deadline : null), $jsonData->completed);
            $title = $newTask->getTitle();
            $description = $newTask->getDescription();
            $deadline = $newTask->getDeadline();
            $completed = $newTask->getCompleted();
            $query = $writeDB->prepare('INSERT INTO tbl_tasks (title, description, deadline, completed) VALUES (:title, :description, STR_TO_DATE(:deadline, "%d/%m/%Y %H:%i"), :completed)');
            $query->bindParam(':title', $title, PDO::PARAM_STR);
            $query->bindParam(':description', $description, PDO::PARAM_STR);
            $query->bindParam(':deadline', $deadline, PDO::PARAM_STR);
            $query->bindParam(':completed', $completed, PDO::PARAM_STR);
            $query->execute();
            $rowCount = $query->rowCount();
            if ($rowCount === 0) {
                $response = new Response();
                $response->setHttpStatusCode(500);
                $response->setSuccess(false);
                $response->addMessage("Failed to create task");
                $response->send();
                exit;
            }
            $lastTaskID = $writeDB->lastInsertId();
            $query = $writeDB->prepare('SELECT id, title, description, DATE_FORMAT(deadline, "%d/%m/%Y %H:%i") as deadline, completed FROM tbl_tasks WHERE id = :taskid');
            $query->bindParam(':taskid', $lastTaskID, PDO::PARAM_INT);
            $query->execute();
            $rowCount = $query->rowCount();
            if ($rowCount === 0) {
                $response = new Response();
                $response->setHttpStatusCode(500);
                $response->setSuccess(false);
                $response->addMessage("Failed to retrieve task after creation");
                $response->send();
                exit;
            }
            $taskArray = array();
            while ($row = $query->fetch(PDO::FETCH_ASSOC)) {
                $task = new Task($row['id'], $row['title'], $row['description'], $row['deadline'], $row['completed']);
                $taskArray[] = $task->returnTaskAsArray();
            }
            $returnData = array();
            $returnData['rows_returned'] = $rowCount;
            $returnData['tasks'] = $taskArray;
            $response = new Response();
            $response->setHttpStatusCode(201);
            $response->setSuccess(true);
            $response->addMessage("Task created");
            $response->setData($returnData);
            $response->send();
            exit;
        } catch (TaskException $ex) {
            $response = new Response();
            $response->setHttpStatusCode(400);
            $response->setSuccess(false);
            $response->addMessage($ex->getMessage());
            $response->send();
            exit;
        } catch (PDOException $ex) {
            error_log("Database query error - " . $ex, 0);
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage("Failed to insert task into database - check your data for errors");
            $response->send();
            exit;
        }
    }
} else {
    $response = new Response();
    $response->setHttpStatusCode(404);
    $response->setSuccess(false);
    $response->addMessage("Endpoint not found");
    $response->send();
    exit;
}
