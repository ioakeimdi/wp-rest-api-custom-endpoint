<?php
/*
	Plugin Name: REST API Custom Endpoint
	Description: Add custom endpoint to REST API
	Version: 1.0.0
	Author: id
*/

defined('ABSPATH') || exit;

add_action('rest_api_init', function () {
    register_rest_route(
        'custom/v1',
        '/products',
        array(
            'methods'  => 'POST',
            'callback' => 'custom_prefix_get_v1_products',
            // 'permission_callback' => '__return_true',
            'permission_callback' => 'custom_api_bearer_token_check',
        )
    );
});

function custom_api_bearer_token_check($request)
{
    $headers = $request->get_headers();
    // echo "<hr><pre>HEADERS";
    // print_r($headers);
    // echo "</pre>";

    if (!isset($headers['authorization']) || empty($headers['authorization'])) {
        return new WP_Error('rest_forbidden', 'Authorization Bearer Token is missing.', array('status' => 401));
    }

    $token_parts = explode(" ", reset($headers['authorization']));
    if (count($token_parts) !== 2 || strtolower($token_parts[0]) !== 'bearer') {
        return new WP_Error('rest_forbidden', 'Authorization Bearer Token is missing.', array('status' => 401));
    }

    // $token = $token_parts[1];
    // Here you can add your logic to validate the token
    return true;
}

function custom_prefix_get_v1_products($request)
{
    $data = $request->get_params();

    if ((! isset($data['Username']) || ! isset($data['Password'])) || (empty($data['Username']) || empty($data['Password']))) {
        return new WP_Error('invalid_credentials', 'Invalid username or password.', array('status' => 401));
    }

    $username = sanitize_user($data['Username']);
    $password = sanitize_text_field($data['Password']);

    // Check if the user exists
    $user = get_user_by('login', $username);

    if (!$user) {
        return new WP_Error('invalid_user', 'User not found.', array('status' => 401));
    }

    // Verify the password
    if (!wp_check_password($password, $user->user_pass, $user->ID)) {
        return new WP_Error('invalid_password', 'Invalid password.', array('status' => 401));
    }

    // Check if customer
    // if (!in_array('customer', $user->roles)) {
    //     return new WP_Error('invalid_user_role', 'User must be customer.', array('status' => 401));
    // }

    return 'OK';
}
