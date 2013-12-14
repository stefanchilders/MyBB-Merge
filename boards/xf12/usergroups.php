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

class XF12_Converter_Module_Usergroups extends Converter_Module_Usergroups {
	var $settings = array(
		'friendly_name' => 'usergroups',
		'progress_column' => 'user_group_id',
		'default_per_screen' => 1000,
	);
	
	function import()
	{
		global $import_session, $db;
		
		// Get only the non-staff groups.
		$query = $this->old_db->simple_select("user_group", "*", "user_group_id > 4", array('limit_start' => $this->trackers['start_usergroups'], 'limit' => $import_session['usergroups_per_screen']));
		while($group = $this->old_db->fetch_array($query))
		{
			$gid = $this->insert($group);
			
			// Restore connections
			$db->update_query("users", array('usergroup' => $gid), "import_usergroup = '".intval($group['user_group_id'])."' OR import_displaygroup = '".intval($group['user_group_id'])."'");
		}
	}
	
	function convert_data($data)
	{
		$insert_data = array();
		
		//xenForo values
		$insert_data['import_gid'] = $data['user_group_id'];
		$insert_data['title'] = $data['title'];
		return $insert_data;
	}
	
	function fetch_total()
	{
		global $import_session;
		
		// Get number of usergroups
		if(!isset($import_session['total_usergroups']))
		{
			$query = $this->old_db->simple_select("user_group", "COUNT(*) as count", "user_group_id > 4");
			$import_session['total_usergroups'] = $this->old_db->fetch_field($query, 'count');
			$this->old_db->free_result($query);
		}
		
		return $import_session['total_usergroups'];
	}
}