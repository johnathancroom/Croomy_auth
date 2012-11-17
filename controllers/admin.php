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
				redirect('');
			}
		}
		$this->load->view('croomy_auth/admin/header');
	}

	function index()
	{
		$this->load->view('croomy_auth/admin/home');
	}	
}

/* End of file admin.php */
/* Location: ./application/controllers/admin.php */
