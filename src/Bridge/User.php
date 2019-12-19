<?php

namespace Laravel\Passport\Bridge;

use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\UserEntityInterface;

class User implements UserEntityInterface
{
    use EntityTrait;

    protected $user;

    /**
     * Create a new user instance.
     *
     * @param $userModel
     * @return void
     */
    public function __construct($userModel)
    {
        $this->user = $userModel;
        $this->setIdentifier($userModel->getAuthIdentifier());
    }

    public function user() {
        return $this->user;
    }
}
