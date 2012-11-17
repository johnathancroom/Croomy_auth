<?php if (!defined('BASEPATH')) exit('No direct script access allowed');

class Admin extends CI_Controller
{
	function __construct()
	{
		parent::__construct();

		$this->load->helper('url');
		$this->load->library('croomy_auth');
                if (!$this->croomy_auth->is_logged_in()) {
                        redirect('/auth/login/');
                } else {
                        if ($this->croomy_auth->get_user_id() != $this->config->item('admin_user', 'croomy_auth')) {
                                redirect('/');
                        }
                }
	}

	function index()
	{
		echo 'hello world';
	}
}

/* End of file welcome.php */
/* Location: ./application/controllers/welcome.php */
