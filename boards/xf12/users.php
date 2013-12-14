<?php
/**
 * MyBB 1.6
 * Copyright © 2009 MyBB Group, All Rights Reserved
 *
 * xenForo merge module
 * 
 * Created By: Stefan C.
 */

// Disallow direct access to this file for security reasons
if(!defined("IN_MYBB"))
{
	die("Direct initialization of this file is not allowed.<br /><br />Please make sure IN_MYBB is defined.");
}

class XF12_Converter_Module_Users extends Converter_Module_Users {
	var $settings = array(
		'friendly_name' => 'user',
		'progress_column' => 'user_id',
		'encode_table' => 'user',
		'postnum_column' => 'message_count',
		'username_column' => 'username',
		'email_column' => 'email',
		'default_per_screen' => 1000,
	);
	
	function import()
	{
		global $import_session;
		
		// Get Members
		$query = $this->old_db->query("
				SELECT u.user_id,
				u.username as username,
				u.user_group_id as user_group_id,
				u.secondary_group_ids as secondary_group_ids,
				u.display_style_group_id as display_style_group_id,
				u.email as email,
				u.register_date as register_date,
				u.last_activity as last_activity,
				u.timezone as timezone,
				i.ip as regip,
				a.data as hashdata,
				p.signature as signature
				from xf_user u
				left join xf_ip i on u.user_id = i.user_id AND action='register'
				left join xf_user_authenticate a on a.user_id = u.user_id
				left join xf_user_profile p on p.user_id = u.user_id
				group by u.user_id
				limit ".$this->trackers['start_users'].",".$import_session['users_per_screen']."
				");
		while($user = $this->old_db->fetch_array($query))
		{
			$this->insert($user);
		}
	}
	
	function convert_data($data)
	{
		$insert_data = array();
		
		// xenForo 1.2 values
		$insert_data['usergroup'] = $this->board->get_group_id($data['user_group_id'], array("not_multiple" => true));
		$insert_data['additionalgroups'] = str_replace($insert_data['usergroup'], '', $this->board->get_group_id($data['secondary_group_ids']));
		$insert_data['displaygroup'] = $this->board->get_group_id($data['display_style_group_id'], array("not_multiple" => true));
		$insert_data['import_uid'] = $data['user_id'];
		$insert_data['username'] = encode_to_utf8($data['username'], "user", "users");
		$insert_data['email'] = $data['email'];
		$insert_data['regdate'] = $data['register_date'];
		$insert_data['lastactive'] = $data['last_activity'];
		$time = new \DateTime('now', new DateTimeZone($data['timezone']));
		$offset_seconds = $time->format('Z');
		$offset = floor($offset_seconds / 3600).".".floor(($offset_seconds - (floor($offset_seconds / 3600) * 3600)) / 60);
		$insert_data['timezone'] = str_replace(array('.0','.00'), array('',''), $offset);
		$insert_data['style'] = 0;
		
		$insert_data['regip'] = long2ip($data['regip']);
		
		$insert_data['totalpms'] = 0;
		$insert_data['unreadpms'] = 0;
		
		$data = unserialize($data['hashdata']);
		$insert_data['passwordconvert'] = $data['hash'];
		$insert_data['passwordconverttype'] = 'xf12';
		
		$insert_data['signature'] = $data['signature'];
		return $insert_data;
	}
	
	function fetch_total()
	{
		global $import_session;
		
		// Get number of members
		if(!isset($import_session['total_users']))
		{
			$query = $this->old_db->simple_select("user", "COUNT(*) as count");
			$import_session['total_users'] = $this->old_db->fetch_field($query, 'count');
			$this->old_db->free_result($query);
		}
		
		return $import_session['total_users'];
	}
}