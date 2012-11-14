<?php if (!defined('BASEPATH')) exit('No direct script access allowed');

/*
|--------------------------------------------------------------------------
| Website details
|
| These details are used in emails sent by authentication library.
|--------------------------------------------------------------------------
*/
$config['website_name'] = 'XLREader test';
$config['webmaster_email'] = 'david@delcoe.com';

/*
|--------------------------------------------------------------------------
| Registration settings
|
| 'allow_registration' = Registration is enabled or not
| 'captcha_registration' = Registration uses CAPTCHA
| 'email_activation' = Requires user to activate their account using email after registration.
| 'email_activation_expire' = Time before users who don't activate their account getting deleted from database. Default is 48 hours (60*60*24*2).
| 'email_account_details' = Email with account details is sent after registration (only when 'email_activation' is FALSE).
| 'use_username' = Username is required or not.
|
| 'username_min_length' = Min length of user's username.
| 'username_max_length' = Max length of user's username.
| 'password_min_length' = Min length of user's password.
| 'password_max_length' = Max length of user's password.
|--------------------------------------------------------------------------
*/
$config['allow_registration'] = TRUE;
$config['captcha_registration'] = FALSE;
$config['email_activation'] = TRUE;
$config['email_activation_expire'] = 60*60*24*2;
$config['email_account_details'] = TRUE;
$config['use_username'] = TRUE;

$config['username_min_length'] = 4;
$config['username_max_length'] = 20;
$config['password_min_length'] = 4;
$config['password_max_length'] = 20;

/*
|--------------------------------------------------------------------------
| User approval option
|
| Set equal to TRUE to have an e-mail sent to $config['webmaster_email'] each time a user
| registers to have them either approved or denied. Users will not be able to login until
| they are both approved by the webmaster and (if enabled) verify their e-mail address.
|--------------------------------------------------------------------------
*/
$config['admin_approval'] = TRUE;

/*
|--------------------------------------------------------------------------
| Login settings
|
| 'login_by_username' = Username can be used to login.
| 'login_by_email' = Email can be used to login.
| You have to set at least one of 2 settings above to TRUE.
| 'login_by_username' makes sense only when 'use_username' is TRUE.
|
| 'login_record_ip' = Save in database user IP address on user login.
| 'login_record_time' = Save in database current time on user login.
|
| 'login_count_attempts' = Count failed login attempts.
| 'login_max_attempts' = Number of failed login attempts before CAPTCHA will be shown.
| 'login_attempt_expire' = Time to live for every attempt to login. Default is 24 hours (60*60*24).
|--------------------------------------------------------------------------
*/
$config['login_by_username'] = TRUE;
$config['login_by_email'] = TRUE;
$config['login_record_ip'] = TRUE;
$config['login_record_time'] = TRUE;
$config['login_count_attempts'] = TRUE;
$config['login_max_attempts'] = 5;
$config['login_attempt_expire'] = 60*60*24;

/*
|--------------------------------------------------------------------------
| Additional registration fields
|
| Additional registration fields can be specified using an array. They will be
| added to the registration form and inputted into either the `users` table
| or into another user-specified table. 
| 
| Arrays should use the following convention:
| $config['additional_reg_fields'] = array(
|    array(
|       'name' 			 => 'form_name', # Required
|       'public_name'		 => 'Form Name', # Required
|       'form_validation'	 => 'required|trim|max_length[10]', # Required
|	'database_column'	 => 'my_table.form_name', # Default is users.[name]
|	'input_type'		 => 'text', # If 'text', this is not required. text|checkbox|radio|dropdown
|				 	    # if checkbox, radio, or dropdown, an input_options array is
|					    # required with keys and values for the options
|	'input_options' 	 => 'class="input-class" id="input-id"',
|		
|    ),
| );  
| 
| As for the $config['table_settings'] value, you must set the column that will contain the newly-generated
| user id. If a column for a particular table is not set, then it will default to 'user_id'.
| 
| Using the previous field as an example, if you wanted the newly-generated user ID to go into the 'user'
| column of the `my_table` table, you could set the directive like this:
| $config['table_settings'] = array(
|	'my_table' => 'user'
| );
|
|--------------------------------------------------------------------------
*/
$config['additional_reg_fields'] = array(
	array(
		'name' => 'testing',
		'public_name' => 'Testing',
		'form_validation' => 'required',
		'database_column' => 'data.david',
		'input_type' 	=> 'text'
	)
);
$config['table_settings'] = array('data' => 'user');

/*
|--------------------------------------------------------------------------
| Auto login settings
|
| 'autologin_cookie_name' = Auto login cookie name.
| 'autologin_cookie_life' = Auto login cookie life before expired. Default is 2 months (60*60*24*31*2).
|--------------------------------------------------------------------------
*/
$config['autologin_cookie_name'] = 'autologin';
$config['autologin_cookie_life'] = 60*60*24*31*2;

/*
|--------------------------------------------------------------------------
| Forgot password settings
|
| 'forgot_password_expire' = Time before forgot password key become invalid. Default is 15 minutes (60*15).
|--------------------------------------------------------------------------
*/
$config['forgot_password_expire'] = 60*15;

/*
|--------------------------------------------------------------------------
| Captcha
|
| You can set captcha that created by Auth library in here.
| 'captcha_path' = Directory where the catpcha will be created.
| 'captcha_fonts_path' = Font in this directory will be used when creating captcha.
| 'captcha_font_size' = Font size when writing text to captcha. Leave blank for random font size.
| 'captcha_grid' = Show grid in created captcha.
| 'captcha_expire' = Life time of created captcha before expired, default is 3 minutes (180 seconds).
| 'captcha_case_sensitive' = Captcha case sensitive or not.
|--------------------------------------------------------------------------
*/
$config['captcha_path'] = 'captcha/';
$config['captcha_fonts_path'] = 'captcha/fonts/5.ttf';
$config['captcha_width'] = 200;
$config['captcha_height'] = 50;
$config['captcha_font_size'] = 14;
$config['captcha_grid'] = FALSE;
$config['captcha_expire'] = 180;
$config['captcha_case_sensitive'] = TRUE;

/*
|--------------------------------------------------------------------------
| reCAPTCHA
|
| 'use_recaptcha' = Use reCAPTCHA instead of common captcha
| You can get reCAPTCHA keys by registering at http://recaptcha.net
|--------------------------------------------------------------------------
*/
$config['use_recaptcha'] = FALSE;
$config['recaptcha_public_key'] = '';
$config['recaptcha_private_key'] = '';

/*
|--------------------------------------------------------------------------
| Database settings
|
| 'db_table_prefix' = Table prefix that will be prepended to every table name used by the library
| (except 'ci_sessions' table).
|--------------------------------------------------------------------------
*/
$config['db_table_prefix'] = '';


/* End of file tank_auth.php */
/* Location: ./application/config/tank_auth.php */