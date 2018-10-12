<?php

declare(strict_types = 1);

namespace Vaalyn\AuthenticationService\Validator;

use stdClass;

interface AuthenticationUserObjectValidatorInterface {
	/**
	 * @param stdClass $user
	 *
	 * @return void
	 */
	public function validate(stdClass $user): void;
}
