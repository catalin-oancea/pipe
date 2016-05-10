<?php
require_once __DIR__.'/../vendor/autoload.php';
use Silex\Application;
use Symfony\Component\HttpFoundation\Request;

$app = new Silex\Application();

$app['debug'] = true;
$app['static_salt'] = "";

$app->register(new Silex\Provider\TwigServiceProvider(), array(
	'twig.path' => __DIR__.'/../templates',
));

$app->register(new Silex\Provider\DoctrineServiceProvider(), array(
	'db.options' => array(
		'driver'   => 'pdo_mysql',
		'host' => 'localhost',
		'dbname' => 'ip_project',
		'username' => 'root',
		'password' => '',
		'charset' => 'latin1'
	),
));

$getHashedPassword = function($password) use ($app) {
	return hash('sha256', $password.$app['static_salt']);
};

$getAuthKey = function($user_id, $user_name, $valid_until) use ($app) {
	return hash('sha256', $user_id.$user_name.$valid_until.$app['static_salt']);
};

$getFileName = function($date, $uid, $gid, $random, $file_ext) use ($app) {
	return $gid.'-'.$uid.'-file-'.hash('sha256',$date.$random).'.'.$file_ext;
};

/**
 * This is a decorator that adds request headers (from cookies)
 * @param Request $request
 * @return null
 */
$alterRequestHeaders = function(Request $request) {
	$cookies = $request->cookies;
	if($cookies->has('id') && $cookies->has('username') && $cookies->has('valid_until') && $cookies->has('auth_key')){
		$request->headers->set('X-Id', $cookies->get('id'));
		$request->headers->set('X-Username', $cookies->get('username'));
		$request->headers->set('X-Valid-Until', $cookies->get('valid_until'));
		$request->headers->set('X-Auth-Key', $cookies->get('auth_key'));
	}
	return null;
};
$checkIfUsernameValid = function(Request $request, Application $app) {
	$username = $request->get('username');
	if(strlen($username) > 2)
		return null;
	else
		return $app->json(array('status'=>'failed', 'error'=>'username must be at least 3 characters'));
};
$checkIfEmailValid = function(Request $request, Application $app) {
	$email = $request->get('email');
	if(filter_var($email, FILTER_VALIDATE_EMAIL))
		return null;
	else
		return $app->json(array('status'=>'failed', 'error'=>'email address appears to be invalid'));

};
$checkIfPasswordValid = function(Request $request, Application $app) {
	$password = $request->get('password');
	if(strlen($password) > 4)
		return null;
	else
		return $app->json(array('status'=>'failed', 'error'=>'password must be at least 5 characters'));
};
$checkIfAuthenticated = function (Request $request, Application $app) use ($getAuthKey) {
	$id = $request->headers->get('X-Id');
	$username = $request->headers->get('X-Username');
	$valid_until = $request->headers->get('X-Valid-Until');
	$auth_key = $request->headers->get('X-Auth-Key');

	if(gmdate('Y-m-d H:i:s') > $valid_until)
		return $app->json(array('status'=>'failed', 'error'=>'auth key expired'));

	$computed_key = $getAuthKey($id, $username, $valid_until);

	if($computed_key !== $auth_key)
		return $app->json(array('status'=>'failed', 'error'=>'auth key mismatch'));
	else
		return null;
};
$checkIfUserExists = function (Request $request, Application $app) use ($app) {
	$uid = $request->get('uid');
	$user = $app['db']->fetchAssoc(
		'SELECT * '.
		'FROM core_user '.
		'WHERE id = ?',
		array(
			$uid
		)
	);
	if($user)
		return null;
	else
		return $app->json(array('status'=>'failed', 'error'=>'given user id does not exist'));
};
$checkUsernameAvailability = function (Request $request, Application $app) {
	$username = $request->get('username');
	$user = $app['db']->fetchAssoc(
		'SELECT * '.
		'FROM core_user '.
		'WHERE username = ?',
		array(
			$username
		)
	);
	if($user)
		return $app->json(array('status'=>'failed', 'error'=>'username taken'));
	else
		return null;
};
$checkEmailAddressAvailability = function (Request $request, Application $app) {
	$email = $request->get('email');
	$user = $app['db']->fetchAssoc(
		'SELECT * '.
		'FROM core_user '.
		'WHERE email = ?',
		array(
			$email
		)
	);
	if($user)
		return $app->json(array('status'=>'failed', 'error'=>'email address taken'));
	else
		return null;
};

$changeDataType = function (Request $request) {
	if (0 === strpos($request->headers->get('Content-Type'), 'application/json') && $request->getMethod() === 'POST') {
		$data = json_decode($request->getContent(), true);
		$request->request->replace(is_array($data) ? $data : array());
	}
};

/**
 * Web client section
 */
$app->get('/', function () use($app) {
	return $app['twig']->render('login_page.html', array());
});

$app->get('/check_auth', function() use($app) {
	return $app->json(array('success'=>'user is authenticated'));
})
	->before($alterRequestHeaders)
	->before($checkIfAuthenticated);

$app->get('/pipe', function() use($app) {
	return $app['twig']->render('pipe.html', array());
})
	->before($alterRequestHeaders)
	->before($checkIfAuthenticated);

/**
 * RESTful API section
 */
$app->before($changeDataType);

$app->post('/authenticate', function(Request $request) use ($app, $getHashedPassword, $getAuthKey) {
	$username = $request->get('username');
	$password = $request->get('password');

	$password_h = $getHashedPassword($password);

	$user = $app['db']->fetchAssoc(
		'SELECT * '.
		'FROM core_user '.
		'WHERE username = ?',
		array(
			$username
		)
	);
	$response = array();

	if ($user && $user['password'] === $password_h)
	{
		$valid_until = gmdate("Y-m-d H:i:s", strtotime("+1 week"));
		$response['status'] = "success";
		$response['authenticate_data'] = array(
			'id'=>$user['id'],
			'username'=>$user['username'],
			'email'=>$user['email'],
			'valid_until'=>$valid_until,
			'auth_key'=>$getAuthKey($user['id'], $user['username'], $valid_until)
		);
		return $app->json($response);
	}
	$response['status'] = "failed";
	$response['error'] = "username/password combination wrong";
	return $app->json($response);
});

$app->post('/register', function (Request $request) use($app, $getHashedPassword) {
	$username = $request->get('username');
	$email = $request->get('email');
	$password = $request->get('password');
	$first_name = $request->get('first_name');
	$last_name = $request->get('last_name');
	$gender = $request->get('gender');

	if(!$first_name) return $app->json(array('status'=>'failed', 'error'=>'first name not provided'));
	if(!$last_name) return $app->json(array('status'=>'failed', 'error'=>'last name not provided'));
	if(!$gender || ($gender != 'M' && $gender != 'F' && $gender != 'N/A')) return $app->json(array('status'=>'failed', 'error'=>'gender not provided'));

	$date_added = gmdate('Y-m-d H:i:s');
	$password_h = $getHashedPassword($password);

	$insert_status = $app['db']->executeUpdate(
		'INSERT '.
		'INTO core_user (username, email, password, date_added, profile_picture, first_name, last_name, gender) '.
		'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
		array(
			$username,
			$email,
			$password_h,
			$date_added,
			'default-profile-picture.jpg',
			$first_name,
			$last_name,
			$gender
		)
	);
	if($insert_status == 1)
		return $app->json(array('status'=>'success'));
	else
		return $app->json(array('status'=>'failed', 'error'=>'database transaction failed with status '.$insert_status));
})
	->before($checkIfUsernameValid)
	->before($checkIfEmailValid)
	->before($checkIfPasswordValid)
	->before($checkUsernameAvailability)
	->before($checkEmailAddressAvailability);

//TODO: Check if user is authorized
//TODO: Return status=failed if db transaction fails
$app->get('/user/{uid}', function($uid) use ($app) {
	$user = $app['db']->fetchAssoc(
		'SELECT id, username, email, date_added, profile_picture '.
		'FROM core_user WHERE id = ?',
		array(
			$uid
		)
	);
	return $app->json(array('user'=>$user));
})
	->before($alterRequestHeaders)
	->before($checkIfAuthenticated)
	->before($checkIfUserExists);

//TODO: Return status=failed if db transaction fails
$app->get('/find_user/{search_string}', function(Request $request, $search_string) use ($app) {
	$uid = $request->headers->get('X-Id');

	$users = $app['db']->fetchAll(
		'SELECT u.id, u.username, u.email, u.profile_picture, u.date_added, '.
		'(SELECT CASE '.
		'	WHEN ('.
		'			SELECT COUNT(x.id) '.
		'			FROM core_user_x_user AS x '.
		'			WHERE x.user_id_b = u.id AND x.user_id_a = ? '.
		'	) > 0 THEN 1 ELSE 0 END '.
		') AS is_friend, '.
		'(SELECT CASE '.
		'	WHEN ( '.
		'		SELECT COUNT(y.from_user) '.
		'		FROM core_friend_request AS y '.
		'		WHERE y.from_user = ? AND y.to_user = u.id '.
		'	) > 0 THEN 1 ELSE 0 END '.
		') AS pending_request, '.
		'(SELECT CASE '.
		'	WHEN ( '.
		'		SELECT COUNT(z.to_user) '.
		'		FROM core_friend_request AS z '.
		'		WHERE z.from_user = u.id AND z.to_user = ? '.
		'	) > 0 THEN 1 ELSE 0 END '.
		') AS pending_aproval, '.
		'(SELECT t.id '.
		'	FROM core_friend_request AS t '.
		'	WHERE ((t.to_user = ? AND t.from_user = u.id) OR (t.from_user = ? AND t.to_user = u.id)) '.
		') AS friend_req_id '.
		'FROM core_user as u '.
		'WHERE ((u.email LIKE ? OR u.username LIKE ?) AND u.id <> ?) '.
		'ORDER BY u.id ASC LIMIT 5',
		array(
			$uid,
			$uid,
			$uid,
			$uid,
			$uid,
			'%'.$search_string.'%',
			'%'.$search_string.'%',
			$uid
		)
	);
	$response = new \Symfony\Component\HttpFoundation\JsonResponse();
	$response->setContent(json_encode(array('status' => 'success', 'users' => $users), JSON_NUMERIC_CHECK));

	return $response;
})
	->before($alterRequestHeaders)
	->before($checkIfAuthenticated);

$app->post('/friend_request', function(Request $request) use ($app) {
	$from_user = $request->get('from_id');
	$to_user = $request->get('to_id');

	$insert_status = $app['db']->executeUpdate(
		'INSERT '.
		'INTO core_friend_request (from_user, to_user) '.
		'VALUES (?, ?)',
		array(
			$from_user,
			$to_user
		)
	);
	if($insert_status == 1)
		return $app->json(array('status'=>'success'));
	else
		return $app->json(array('status'=>'failed', 'error'=>'database transaction failed with status '.$insert_status));
})
	->before($alterRequestHeaders)
	->before($checkIfAuthenticated);

//TODO: Check if user is authorized
//TODO: Return status=failed if db transaction fails
$app->get('/friend_request/{uid}', function($uid) use ($app) {
	$requests = $app['db']->fetchAll(
		'SELECT a.id AS request_id, a.from_user AS from_user, '.
		'a.to_user AS to_user, b.username AS from_username, '.
		'b.email AS from_email, b.profile_picture AS from_profile_picture '.
		'FROM core_friend_request AS a '.
		'JOIN core_user AS b ON b.id = a.from_user '.
		'WHERE a.to_user = ?;',
		array(
			$uid
		)
	);
	return $app->json(array('status'=>'success', 'requests'=>$requests));
})
	->before($alterRequestHeaders)
	->before($checkIfAuthenticated)
	->before($checkIfUserExists);


//TODO: Must refactor this with PUT /friend_request/{frid}
//TODO: Check if user is authorized
$app->post('/handle_friend_request/{frid}', function(Request $request, $frid) use ($app) {
	$request_response = $request->get('request_response');

	if($request_response != "accept" && $request_response != "decline")
		return $app->json(array('status'=>'failed', 'error'=>'request_response should be either accept or decline'));

	$rc1 = 1;
	if ($request_response == "accept") {
		$rc1 = $app['db']->executeUpdate(
			'INSERT '.
			'INTO core_user_x_user (user_id_a, user_id_b) '.
			'SELECT from_user, to_user '.
			'FROM core_friend_request WHERE id = ?; '.

			'INSERT '.
			'INTO core_user_x_user (user_id_a, user_id_b) '.
			'SELECT to_user, from_user '.
			'FROM core_friend_request WHERE id = ?; ',
			array(
				$frid,
				$frid
			)
		);
	}
	$rc2 = $app['db']->executeUpdate(
		'DELETE '.
		'FROM core_friend_request WHERE id = ? ',
		array(
			$frid
		)
	);

	if($rc1 != 1 || $rc2 != 1)
		return $app->json(array('status'=>'failed', 'error'=>'database transaction failed with code '.$rc1.'-'.$rc2.' (did rollback)'));
	else
		return $app->json(array('status'=>'success'));

})
	->before($alterRequestHeaders)
	->before($checkIfAuthenticated);

//TODO: Check if user is authorized
//TODO: Return status=failed if db transaction fails
$app->delete('/friend_request/{frid}', function($frid) use ($app){
	$rc = $app['db']->executeUpdate(
		'DELETE '.
		'FROM core_friend_request WHERE id = ? ',
		array(
			$frid
		)
	);
	if($rc != 1)
		return $app->json(array('status'=>'failed', 'error'=>'database transaction failed with code '.$rc));
	else
		return $app->json(array('status'=>'success'));
})
	->before($alterRequestHeaders)
	->before($checkIfAuthenticated);

//TODO: Check if user is authorized
//TODO: Return status=failed if db transaction fails
$app->get('/friends_of/{uid}', function($uid) use ($app) {
	$friends = $app['db']->fetchAll(
		'SELECT cu.id AS id, cu.username AS username, cu.email AS email, cu.date_added as date_added, cu.profile_picture as profile_picture '.
		'FROM core_user AS cu '.
		'WHERE cu.id IN ('.
		'SELECT uxu.user_id_b '.
		'FROM core_user_x_user AS uxu '.
		'WHERE uxu.user_id_a = ?'.
		');',
		array($uid)
	);

	return $app->json(array('status'=>'success', 'friends'=>$friends));
})
	->before($alterRequestHeaders)
	->before($checkIfAuthenticated)
	->before($checkIfUserExists);

//TODO: Return status=failed if db transaction fails
$app->post('/upload/profile_picture', function(Request $request) use ($app, $getFileName) {
	$file = $request->files->get('user_profile');
	if(getimagesize($file)){
		$file_ext = $file->guessExtension();

		$path = __DIR__.'/../uploads';

		$uid = $request->headers->get('X-Id');
		$filename = $getFileName(gmdate('Y-m-d H:i:s'), $uid, 0, rand(0, $uid), $file_ext);

		$file->move($path, $filename);
		$app['db']->executeUpdate(
			'UPDATE core_user '.
			'SET profile_picture = ? '.
			'WHERE id = ?',
			array(
				$filename,
				$uid
			)
		);

		return $app->json(array('status'=>'success', 'file_name'=>$filename));
	} else
		return $app->json(array('status'=>'failed', 'error'=>'not an image'));

})
	->before($alterRequestHeaders)
	->before($checkIfAuthenticated);

//TODO: Check if user is authorized
$app->get('/file/{filename}', function($filename) use ($app) {
	$file = __DIR__.'/../uploads/'.$filename;
	if(file_exists($file))
		return $app->sendFile($file);
	else
		return $app->json(array('status'=>'failed', 'error'=>'file requested does not exist'));
})
	->before($alterRequestHeaders)
	->before($checkIfAuthenticated);

//TODO: Return status=failed if db transaction fails
$app->post('/group/new', function(Request $request) use ($app) {
	$initiator_id = $request->get('initiator_id');
	$other_users = $request->get('member_ids');
	$message = $request->get('message');
	$group_name = $request->get('group_name');

	if(!$message)
		return $app->json(array('status'=>'failed', 'error'=>'no message provided'));
	if(!$other_users)
		return $app->json(array('status'=>'failed', 'error'=>'no group participants provided'));

	$current_time = gmdate('Y-m-d H:i:s');
	$all_members = $other_users.','.$initiator_id;
	$all_members_arr = explode(",", $all_members);

	if (!$group_name) {
		if(count($all_members_arr) > 2)
			$group_name = "group-".substr(str_shuffle(str_repeat("01234567890123456789012345678901234567890123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", 5)), 0, 5);
		else
			$group_name = "";
	}
	if(count($all_members_arr) > 2)
		$group_avatar = "group-avatar-".rand(0,17).".jpg";
	else
		$group_avatar = "";


	$app['db']->beginTransaction();

	$app['db']->executeUpdate(
		'INSERT '.
		'INTO core_group (date_created, name, avatar) '.
		'VALUES (?, ?, ?)',
		array(
			$current_time,
			$group_name,
			$group_avatar
		)

	);

	$group_id = $app['db']->lastInsertId();

	foreach($all_members_arr as $member_id){
		$app['db']->executeUpdate(
			'INSERT '.
			'INTO core_group_x_user (group_id, user_id) '.
			'VALUES (?, ?)',
			array(
				$group_id,
				$member_id
			)

		);
	}

	$app['db']->executeUpdate(
		'INSERT '.
		'INTO core_message (source_id, group_id, message, date_added) '.
		'VALUES (?, ?, ?, ?)',
		array(
			$initiator_id,
			$group_id,
			$message,
			$current_time
		)

	);

	$app['db']->commit();
	return $app->json(array('status'=>'success'));

})
	->before($alterRequestHeaders)
	->before($checkIfAuthenticated);

//TODO: Return status=failed if db transaction fails
$app->get('/group/list/{uid}', function($uid) use ($app) {
	$group_list = $app['db']->fetchAll(
		'SELECT GXU.group_id, GXU.last_msg_read_id, G.date_created as group_date_created, '.
		'(CASE G.name '.
    	'	WHEN "" THEN (SELECT CONCAT(first_name, \' \', last_name) FROM core_user WHERE id = (SELECT user_id FROM core_group_x_user WHERE user_id <> GXU.user_id AND group_id = GXU.group_id)) '.
    	'	ELSE (SELECT G.name) '.
		'END) group_name, '.
		'(CASE G.avatar '.
    	'	WHEN "" THEN (SELECT profile_picture FROM core_user WHERE id = (SELECT user_id FROM core_group_x_user WHERE user_id <> GXU.user_id AND group_id = GXU.group_id)) '.
    	'	ELSE (SELECT G.avatar)'.
		'END) avatar, '.
		'M.message, M.source_id as msg_source_uid, M.id as msg_id, M.date_added as last_msg_time '.
		'FROM core_group_x_user GXU '.
		'JOIN core_group G ON G.id = GXU.group_id '.
		'JOIN core_message M ON M.group_id = GXU.group_id AND M.date_added = ( '.
		'	SELECT MAX(date_added) '.
    	'	FROM core_message '.
    	'	WHERE group_id = GXU.group_id '.
		') '.
		'WHERE GXU.user_id = ? '.
		'GROUP BY GXU.group_id '.
		'ORDER BY M.date_added DESC;',
		array(
			$uid
		)
	);

	return $app->json(array('status'=>'success', 'group_list'=>$group_list));
})
	->before($alterRequestHeaders)
	->before($checkIfAuthenticated);

//TODO: Check if user is authorized
//TODO: Return status=failed if db transaction fails
$app->get('/message/list/{gid}', function($gid) use ($app) {
	$message_list = $app['db']->fetchAll(
		'SELECT * '.
		'FROM ( '.
		'	SELECT M.id as message_id, M.message, M.date_added, U.id as user_id, U.username as source_name, U.profile_picture as source_profile_picture '.
		'	FROM core_message M '.
		'	JOIN core_user U ON U.id = M.source_id '.
		'	WHERE M.group_id = ? '.
		'	ORDER BY M.date_added DESC '.
		'	LIMIT 70 '.
		') A ORDER BY A.date_added ASC',
		array(
			$gid
		)
	);

	return $app->json(array('status'=>'success', 'group_id'=> $gid ,'message_list'=>$message_list));
})
	->before($alterRequestHeaders)
	->before($checkIfAuthenticated);

//TODO: Check if user is authorized
//TODO: Return status=failed if db transaction fails
$app->post('/message', function(Request $request) use ($app) {
	$source_id = $request->get('user_id');
	$group_id = $request->get('group_id');
	$message = $request->get('message');

	if(!$message)
		return $app->json(array('status'=>'failed', 'error'=>'no message provided'));

	$curr_date = gmdate('Y-m-d H:i:s');

	$app['db']->executeUpdate(
		'INSERT '.
		'INTO core_message (source_id, group_id, message, date_added) '.
		'VALUES (?, ?, ?, ?)',
		array(
			$source_id,
			$group_id,
			$message,
			$curr_date
		)
	);

	return $app->json(array('status'=>'success'));
})
	->before($alterRequestHeaders)
	->before($checkIfAuthenticated);

//TODO: Check if user is authorized
//TODO: Return status=failed if db transaction fails
$app->post('/message/mark_read', function(Request $request) use ($app) {
	$user_id = $request->get('user_id');
	$message_id = $request->get('message_id');
	$group_id = $request->get('group_id');

	$app['db']->executeUpdate(
		'UPDATE core_group_x_user '.
		'SET last_msg_read_id = ? '.
		'WHERE group_id = ? AND user_id = ?',
		array(
			$message_id,
			$group_id,
			$user_id
		)
	);

	return $app->json(array('status'=>'success'));
})
	->before($alterRequestHeaders)
	->before($checkIfAuthenticated);


$app->run();

