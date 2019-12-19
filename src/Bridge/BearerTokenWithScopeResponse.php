<?php

namespace Laravel\Passport\Bridge;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;

class BearerTokenWithScopeResponse extends \League\OAuth2\Server\ResponseTypes\BearerTokenResponse
{
    /**
     * Add custom fields to your Bearer Token response here, then override
     * AuthorizationServer::getResponseType() to pull in your version of
     * this class rather than the default.
     *
     * @param AccessTokenEntityInterface $accessToken
     *
     * @return array
     */
    protected function getExtraParams(AccessTokenEntityInterface $accessToken)
    {
        return ['scopes' => collect($accessToken->getScopes())->map(function (ScopeEntityInterface $scopeEntity) {
            return $scopeEntity->getIdentifier();
        })->implode(' ')];
    }
}
