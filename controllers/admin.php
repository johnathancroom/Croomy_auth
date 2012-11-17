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
		$this->load->model('croomy_auth/admin_model');
		$this->load->view('croomy_auth/admin/header');
	}

	function index()
	{
		$this->load->view('croomy_auth/admin/home');
	}
	
	function users() {
		$data['users'] = $this->admin_model->get_all_users();
		$this->load->view('croomy_auth/admin/users', $data);
	}	
	
	function delete_user() {
		if ($id = $this->input->get('id', False)) {
			if (is_numeric($id)) {
				if ($this->admin_model->delete_user($id)) {
					$this->session->set_flashdata('notice', "User $id has been removed");
					redirect('admin/users');
				}
			}
		}
	}
}

/* End of file admin.php */
/* Location: ./application/controllers/admin.php */
