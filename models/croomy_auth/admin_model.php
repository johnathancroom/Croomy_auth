<?php if (!defined('BASEPATH')) exit('No direct script access allowed');

/**
 * Users
 *
 * This model represents user authentication data. It operates the following tables:
 * - user account data,
 *
 * @package     Croomy_auth
 * @author      Ilya Konyukhov (http://konyukhov.com/soft/)
 */
class Admin_model extends CI_Model
{
        function __construct()
        {
                parent::__construct();
		$this->load->database();
	}
	
	function get_all_users() {
		return $this->db->get('users')->result_array();
	}
	
	function delete_user($id) {
		$this->db->where('id', $id); 
		$this->db->delete('users');
		return True;
	}
}
