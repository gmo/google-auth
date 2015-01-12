<?php
namespace GMO\GoogleAuth;

use Google_Client;
use Google_Service_Directory;
use Google_Service_Directory_Group;

class GroupsAuthorization {

	/**
	 * Constructor.
	 * @param Authentication $authentication
	 * @param string $domain The Google Apps domain to check for groups in
	 * @param array $groupEmailAddresses
	 * @throws Exception\ServiceAccountMissing
	 */
	public function __construct(Authentication $authentication, $domain, array $groupEmailAddresses = array()) {
		$this->authentication = $authentication;
		$this->domain = $domain;

		if(!$this->authentication->getServiceClient() instanceof Google_Client) {
			throw new Exception\ServiceAccountMissing();
		}

		$this->service = new Google_Service_Directory($this->authentication->getServiceClient());

		$this->setGroupEmailAddresses($groupEmailAddresses);
	}

	/**
	 * Gets the Group Email addresses to authenticate users against
	 * @return string[]
	 */
	public function getGroupEmailAddresses() {
		return $this->groupEmailAddresses;
	}

	/**
	 * Sets the Group Email addresses to authenticate users against
	 * @param string[] $groupEmailAddresses
	 */
	public function setGroupEmailAddresses(array $groupEmailAddresses) {
		$this->groupEmailAddresses = $groupEmailAddresses;
	}

	/**
	 * Checks if a provided User is in any of the groups
	 * @param User $user
	 * @return bool
	 */
	public function isUserInAnyGroup(User $user) {
		return $this->isUserInAnyProvidedGroup($user, $this->groupEmailAddresses);
	}

	/**
	 * Checks if a provided user is in a specific group
	 * @param User $user
	 * @param string $group
	 * @return bool
	 */
	public function isUserInProvidedGroup(User $user, $group) {
		return $this->isUserInAnyProvidedGroup($user, array($group));
	}

	/**
	 * Checks if a provided user is in any of a set of specific groups
	 * @param User $user
	 * @param array $groupEmailAddresses
	 * @return bool
	 */
	public function isUserInAnyProvidedGroup(User $user, array $groupEmailAddresses) {
		$userGroups = $this->getGroupsEmailAddressesForUser($user->getEmail());
		$commonGroups = array_intersect($userGroups, $groupEmailAddresses);
		return !empty($commonGroups);
	}

	/**
	 * Checks if a provided user is in all of a set of specific groups
	 * @param User $user
	 * @param array $groupEmailAddresses
	 * @return bool
	 */
	public function isUserInAllProvidedGroups(User $user, array $groupEmailAddresses) {
		$userGroups = $this->getGroupsEmailAddressesForUser($user->getEmail());
		$commonGroups = array_intersect($userGroups, $groupEmailAddresses);
		return count($groupEmailAddresses) === count($commonGroups);
	}

	/**
	 * Gets a list of Groups affiliated with this object's service account
	 * @return \Google_Service_Directory_Groups
	 */
	public function getAllGroupsSummary() {
		return $this->service->groups->listGroups(array(
			'domain' => $this->domain
		));
	}

	/**
	 * Gets an array of all the groups that the provided user is a member of
	 * @param string $userKey
	 * @return string[]
	 */
	public function getGroupsEmailAddressesForUser($userKey) {
		$groupEmails = array();
		$pageToken = null;

		do {
			$params = array(
				'userKey' => $userKey,
				'domain' => $this->domain,
			);
			if(!empty($pageToken)) {
				$params['pageToken'] = $pageToken;
			}
			$results = $this->service->groups->listGroups($params);

			$pageGroupEmails = array_map(function(Google_Service_Directory_Group $group) {
				return $group->getEmail();
			}, $results->getGroups());

			$groupEmails = array_merge($groupEmails, $pageGroupEmails);
			$pageToken = $results->getNextPageToken();
		} while(!empty($pageToken));

		return $groupEmails;
	}

	protected $authentication;
	protected $groupEmailAddresses;
	protected $domain;

	/** @var \Google_Service_Directory */
	protected $service;

	const USER_SCOPE = 'https://www.googleapis.com/auth/admin.directory.user';
	const GROUP_SCOPE = 'https://www.googleapis.com/auth/admin.directory.group';
}