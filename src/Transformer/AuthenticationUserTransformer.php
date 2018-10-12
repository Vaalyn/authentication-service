<?php

declare(strict_types = 1);

namespace Vaalyn\AuthenticationService\Transformer;

use stdClass;
use Vaalyn\AuthenticationService\AuthenticationUser;
use Vaalyn\AuthenticationService\Validator\AuthenticationUserObjectValidator;

class AuthenticationUserTransformer {
	/**
	 * @param stdClass $user
	 *
	 * @return AuthenticationUser
	 */
	public function transformObjectToAuthenticationUser(stdClass $user): AuthenticationUser {
		$authenticationUserObjectValidator = new AuthenticationUserObjectValidator();
		$authenticationUserObjectValidator->validate($user);

		return new AuthenticationUser(
			$user->user_id,
			$user->username,
			$user->email,
			(bool) $user->isAdmin
		);
	}
}
