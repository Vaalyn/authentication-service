<?php

declare(strict_types = 1);

namespace Vaalyn\AuthenticationService\Transformer;

use stdClass;
use Respect\Validation\Exceptions\NestedValidationException;
use Vaalyn\AuthenticationService\AuthenticationUser;
use Vaalyn\AuthenticationService\Exception\UserValidationFailedException;
use Vaalyn\AuthenticationService\Validator\AuthenticationUserObjectValidator;

class AuthenticationUserTransformer {
	/**
	 * @param stdClass $user
	 *
	 * @return AuthenticationUser
	 */
	public function transformObjectToAuthenticationUser(stdClass $user): AuthenticationUser {
		$authenticationUserObjectValidator = new AuthenticationUserObjectValidator();

		try {
			$authenticationUserObjectValidator->validate($user);
		} catch (NestedValidationException $exception) {
			$excpetionMessage = sprintf(
				'User validation for %s failed because of the following reasons:',
				self::class,
				implode(PHP_EOL, $exception->getMessages())
			);

			throw new UserValidationFailedException($excpetionMessage);
		}

		return new AuthenticationUser(
			$user->user_id,
			$user->username,
			$user->email,
			(bool) $user->isAdmin
		);
	}
}
