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

class XF12_Converter extends Converter {

	/**
	 * String of the bulletin board name
	 *
	 * @var string
	 */
	var $bbname = "xenForo 1.2";
	
	/**
	 * String of the plain bulletin board name
	 *
	 * @var string
	 */
	var $plain_bbname = "xenForo 1.2";
	
	/**
	 * Whether or not this module requires the loginconvert.php plugin
	 *
	 * @var boolean
	 */
	var $requires_loginconvert = true;
	
	/**
	 * Array of all the modules
	 * @var array
	 */
	var $modules = array("db_configuration" => array("name" => "Database Configuration", "dependencies" => ""),
						 "import_users" => array("name" => "Users", "dependencies" => "db_configuration"),
						 "import_usergroups" => array("name" => "Usergroups", "dependencies" => "db_configuration,import_users"),
						);
	
	/**
	 * Convert a xenForo group ID into a MyBB group ID
	 * 
	 * @param int Group ID
	 * @param array Options for retreiving the group ids
	 * @return mixed group id(s)
	 */
	function get_group_id($gid, $options=array())
	{
		static $groupcache;
		if(!isset($groupcache))
		{
			$groupcache = array();
			$query = $this->old_db->simple_select("user_group", "user_group_id");
			while($xfgroup = $this->old_db->fetch_array($query))
			{
				switch($xfgroup['user_group_id'])
				{
					case 1: // Guest
						$group = 1;
						break;
					case 2: // Member
						$group = 2;
						break;
					case 3: // Administrator
						$group = 4;
						break;
					case 4: // Moderator
						$group = 6;
						break;
					default:
						$group = $this->get_import->gid($xfgroup['user_group_id']);
						if($group <= 0)
						{
							// The lot
							$group = 2;
						}
						break;
				}
				$groupcache[$xfgroup['user_group_id']] = $group;
			}
		}
		if(isset($groupcache[$gid]))
		{
			if($options['origional'] == true)
			{
				return $gid;
			}
			else
			{
				return $groupcache[$gid];
			}
		}
		else
		{
			return 2;
		}
	}
}