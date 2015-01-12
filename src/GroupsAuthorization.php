<?php
namespace GMO\GoogleAuth;

use Google_Client;
use Google_Service_Directory;
use Google_Service_Directory_Group;
use Google_Auth_AssertionCredentials;

class GroupsAuthorization {

	/**
	 * Constructor.
	 * @param string $clientEmail
	 * @param string $privateKeyPath A path to the private key to authenticate the service account with
	 * @param string $adminUser The admin user to impersonate during API calls
	 * @param string $domain The Google Apps domain to check for groups in
	 */
	public function __construct($clientEmail, $privateKeyPath, $adminUser, $domain) {
		$serviceClient = $this->createServiceClient($clientEmail, $privateKeyPath, $adminUser);
		$this->domain = $domain;
		$this->service = new Google_Service_Directory($serviceClient);
	}

	/**
	 * Checks if a provided user is in a specific group
	 * @param User $user
	 * @param string $group
	 * @return bool
	 */
	public function isUserInGroup(User $user, $group) {
		return $this->isUserInAnyGroup($user, array($group));
	}

	/**
	 * Checks if a provided user is in any of a set of specific groups
	 * @param User $user
	 * @param string[] $groupEmailAddresses
	 * @return bool
	 */
	public function isUserInAnyGroup(User $user, array $groupEmailAddresses) {
		$userGroups = $this->getGroupsForUser($user);
		$commonGroups = array_intersect($userGroups, $groupEmailAddresses);
		return !empty($commonGroups);
	}

	/**
	 * Checks if a provided user is in all of a set of specific groups
	 * @param User $user
	 * @param string[] $groupEmailAddresses
	 * @return bool
	 */
	public function isUserInAllGroups(User $user, array $groupEmailAddresses) {
		$userGroups = $this->getGroupsForUser($user);
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
	 * @param User $user
	 * @return string[]
	 */
	public function getGroupsForUser(User $user) {
		$userKey = $user->getEmail();
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

	/**
	 * Creates a Google_Client configured with a service account
	 * @param string $clientEmail
	 * @param string $privateKeyPath A path to the private key to authenticate the service account with
	 * @param string $adminUser The admin user to impersonate during API calls
	 * @return Google_Client
	 */
	protected function createServiceClient($clientEmail, $privateKeyPath, $adminUser) {
		$credentials = new Google_Auth_AssertionCredentials(
			$clientEmail,
			array(
				GroupsAuthorization::GROUP_SCOPE,
				GroupsAuthorization::USER_SCOPE
			),
			file_get_contents($privateKeyPath)
		);
		$credentials->sub = $adminUser;

		$serviceClient = new Google_Client();
		$serviceClient->setAssertionCredentials($credentials);
		if ($serviceClient->getAuth()->isAccessTokenExpired()) {
			$serviceClient->getAuth()->refreshTokenWithAssertion();
		}

		return $serviceClient;
	}

	protected $groupEmailAddresses;
	protected $domain;

	/** @var \Google_Service_Directory */
	protected $service;

	const USER_SCOPE = 'https://www.googleapis.com/auth/admin.directory.user';
	const GROUP_SCOPE = 'https://www.googleapis.com/auth/admin.directory.group';
}