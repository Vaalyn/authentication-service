<?php

declare(strict_types = 1);

namespace Vaalyn\AuthenticationService\Validator;

use stdClass;
use Respect\Validation\Validator;

class AuthenticationUserObjectValidator implements AuthenticationUserObjectValidatorInterface {
	/**
	 * @inheritDoc
	 */
	public function validate(stdClass $user): void {
		Validator::attribute('user_id', Validator::intType())
			->attribute('username', Validator::stringType())
			->attribute('email', Validator::stringType())
			->attribute('is_admin', Validator::boolVal())
			->assert($user);
	}
}
