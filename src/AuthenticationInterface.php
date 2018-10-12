<?php

declare(strict_types = 1);

namespace Vaalyn\AuthenticationService;

use Illuminate\Database\Eloquent\Model;

interface AuthenticationInterface {
	/**
	 * @return AuthenticationUserInterface|null
	 */
	public function user(): ?AuthenticationUserInterface;

	/**
	 * @return bool
	 */
	public function check(): bool;

	/**
	 * @return bool
	 */
	public function isAdmin(): bool;

	/**
	 * @param string $username
	 * @param string $password
	 * @param bool $rememberMe
	 *
	 * @return bool
	 */
	public function attempt(string $username, string $password, bool $rememberMe = false): bool;

	/**
	 * @return void
	 */
	public function invalidateAuthenticationTokens(): void;

	/**
	 * @param Model $authenticationToken
	 *
	 * @return void
	 */
	public function invalidateAuthenticationToken(Model $authenticationToken): void;

	/**
	 * @return void
	 */
	public function logout(): void;

	/**
	 * @param string $routeName
	 *
	 * @return bool
	 */
	public function routeNeedsAuthentication(string $routeName): bool;
}
