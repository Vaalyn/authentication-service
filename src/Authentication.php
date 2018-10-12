<?php

declare(strict_types = 1);

namespace Vaalyn\AuthenticationService;

use Carbon\Carbon;
use Illuminate\Database\Capsule\Manager;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection;
use Jenssegers\Agent\Agent;
use Psr\Container\ContainerInterface;
use Ramsey\Uuid\Uuid;
use Vaalyn\AuthenticationService\Transformer\AuthenticationUserTransformer;
use Vaalyn\SessionService\SessionInterface;

class Authentication implements AuthenticationInterface {
	/**
	 * @var AuthenticationUserTransformer
	 */
	protected $authenticationUserTransformer;

	/**
	 * @var Manager
	 */
	protected $databaseManager;

	/**
	 * @var SessionInterface
	 */
	protected $session;

	/**
	 * @var array
	 */
	protected $cookieConfig;

	/**
	 * @var string[]
	 */
	protected $routesWithAuthentication;

	/**
	 * @param ContainerInterface $container
	 * @param Manager $databaseManager
	 */
	public function __construct(ContainerInterface $container, Manager $databaseManager) {
		$this->authenticationUserTransformer = new AuthenticationUserTransformer();
		$this->databaseManager               = $databaseManager;
		$this->session                       = $container->session;
		$this->cookieConfig                  = $container->config['authentication']['cookie'];
		$this->routesWithAuthentication      = $container->config['authentication']['routes'];
	}

	/**
	 * @inheritDoc
	 */
	public function user(): ?AuthenticationUserInterface {
		$userObject = $this->databaseManager
			->table('user')
			->where('user_id', '=', $this->session->get('user_id'))
			->first();

		if ($userObject !== null) {
			return $this->authenticationUserTransformer
				->transformObjectToAuthenticationUser($userObject);
		}

		return null;
	}

	/**
	 * @inheritDoc
	 */
	public function check(): bool {
		if (!$this->session->exists('user_id')) {
			$this->checkLoginCookie();
		}

		$userExistsInDatabase = $this->databaseManager->table('user')
			->where('user_id', '=', $this->session->get('user_id'))
			->exists();

		if (!$userExistsInDatabase) {
			$this->logout();
		}

		return $this->session->exists('user_id');
	}

	/**
	 * @inheritDoc
	 */
	public function isAdmin(): bool {
		return $this->user()->getIsAdmin();
	}

	/**
	 * @inheritDoc
	 */
	public function attempt(string $username, string $password, bool $rememberMe = false): bool {
		$user = $this->fetchUserByUsername($username);

		if (!isset($user)) {
			return false;
		}

		if (password_verify($password, $user->password)) {
			$this->session->set('user_id', $user->user_id);

			if (password_needs_rehash($user->password, PASSWORD_DEFAULT)) {
				$this->setUserPassword(
					$user->user_id,
					password_hash($password, PASSWORD_DEFAULT)
				);
			}

			if ($rememberMe) {
				$this->setLoginCookie($user->user_id, $user->username);
			}

			return true;
		}

		return false;
	}

	/**
	 * @inheritDoc
	 */
	public function invalidateAuthenticationTokens(): void {
		$invalidationDateTime = new Carbon();
		$invalidationDateTime->subSeconds($this->cookieConfig['expire']);

		$authenticationTokens = $this->databaseManager
			->table('authentication_token')
			->where('created_at', '<', $invalidationDateTime->toDateTimeString())
			->get();

		foreach ($authenticationTokens as $authenticationToken) {
			$this->databaseManager
				->table('authentication_token')
				->where('authentication_token_id', '=', $authenticationToken->authentication_token_id)
				->delete();
		}
	}

	/**
	 * @inheritDoc
	 */
	public function invalidateAuthenticationToken(Model $authenticationToken): void {
		$authenticationToken->delete();
	}

	/**
	 * @inheritDoc
	 */
	public function logout(): void {
		unset($_COOKIE[$this->cookieConfig['name']]);
		setcookie(
			$this->cookieConfig['name'],
			'',
			time() - 3600,
			'/',
			$this->cookieConfig['domain'],
			$this->cookieConfig['secure'],
			$this->cookieConfig['httponly']
		);

		$this->session->destroy();
	}

	/**
	 * @inheritDoc
	 */
	public function routeNeedsAuthentication(string $routeName): bool {
		return in_array($routeName, $this->routesWithAuthentication);
	}

	/**
	 * @param int $userId
	 * @param string $username
	 *
	 * @return void
	 */
	protected function setLoginCookie(int $userId, string $username): void {
		setcookie(
			$this->cookieConfig['name'],
			json_encode([
				'username' => $username,
				'token' => $this->generateLoginCookieToken($userId)
			]),
			time() + $this->cookieConfig['expire'],
			'/',
			$this->cookieConfig['domain'],
			$this->cookieConfig['secure'],
			$this->cookieConfig['httponly']
		);
	}

	/**
	 * @param int $userId
	 *
	 * @return string
	 */
	protected function generateLoginCookieToken(int $userId): string {
		$token = bin2hex(random_bytes(16));

		$browserParser = new Agent();

		$browser = sprintf(
			"Browser: %s\nVersion: %s\nOS: %s\nVersion: %s\nGerät: %s\n",
			$browserParser->browser() ?? '',
			$browserParser->version($browserParser->browser()) ?? '',
			$browserParser->platform() ?? '',
			$browserParser->version($browserParser->platform()) ?? '',
			$browserParser->device() ?? ''
		);

		$authenticationTokenId = Uuid::uuid4()->toString();

		$this->databaseManager
			->table('authentication_token')
			->insert([
				'authentication_token_id' => $authenticationTokenId,
				'user_id'                 => $userId,
				'token'                   => password_hash($token, PASSWORD_DEFAULT),
				'browser'                 => $browser
			]);

		$this->session->set('authentication_token_id', $authenticationTokenId);

		return $token;
	}

	/**
	 * @return void
	 */
	protected function checkLoginCookie(): void {
		$this->invalidateAuthenticationTokens();

		if (isset($_COOKIE[$this->cookieConfig['name']])) {
			$cookie = json_decode($_COOKIE[$this->cookieConfig['name']]);

			$authenticationTokens = $this->fetchAuthenticationTokensByUsername($cookie->username);

			foreach ($authenticationTokens as $authenticationToken) {
				if (password_verify($cookie->token, $authenticationToken->token)) {
					$this->session
						->set('user_id', $authenticationToken->user_id)
						->set('authentication_token_id', $authenticationToken->authentication_token_id);

					break;
				}
			}
		}
	}

	/**
	 * @param string $username
	 *
	 * @return object|null
	 */
	protected function fetchUserByUsername(string $username): ?object {
		return $this->databaseManager
			->table('user')
			->where('username', '=', $username)
			->first();
	}

	/**
	 * @param string $username
	 *
	 * @return Collection
	 */
	protected function fetchAuthenticationTokensByUsername(string $username): Collection {
		return $this->databaseManager
			->table('authentication_token')
			->leftJoin('user', 'authentication_token.user_id', '=', 'user.user_id')
			->where('username', '=', $username)
			->get([
				'authentication_token.*'
			]);
	}

	/**
	 * @param int $userId
	 * @param string $hashedPassword
	 *
	 * @return void
	 */
	protected function setUserPassword(int $userId, string $hashedPassword): void {
		$this->databaseManager
			->table('user')
			->update([
				'password' => $hashedPassword
			]);
	}
}
