<?php

declare(strict_types = 1);

namespace Vaalyn\AuthenticationService;

interface AuthenticationUserInterface {
	/**
	 * @return int
	 */
	public function getUserId(): int;

	/**
	 * @param int $userId
	 *
	 * @return AuthenticationUserInterface
	 */
	public function setUserId(int $userId): AuthenticationUserInterface;

	/**
	 * @return string
	 */
	public function getUsername(): string;

	/**
	 * @param string $username
	 *
	 * @return AuthenticationUserInterface
	 */
	public function setUsername(string $username): AuthenticationUserInterface;

	/**
	 * @return string
	 */
	public function getEmail(): string;

	/**
	 * @param string $email
	 *
	 * @return AuthenticationUserInterface
	 */
	public function setEmail(string $email): AuthenticationUserInterface;

	/**
	 * @return bool
	 */
	public function getIsAdmin(): bool;

	/**
	 * @param bool $isAdmin
	 *
	 * @return AuthenticationUserInterface
	 */
	public function setIsAdmin(bool $isAdmin): AuthenticationUserInterface;
}
