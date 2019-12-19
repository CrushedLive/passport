<?php

namespace Laravel\Passport\Bridge;

use Laravel\Passport\Exceptions\OAuthServerException;
use Laravel\Passport\Passport;
use League\OAuth2\Server\Grant\PasswordGrant as PasswordGrantBase;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;

class PasswordGrant extends PasswordGrantBase
{
    /**
     * {@inheritdoc}
     */
    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        \DateInterval $accessTokenTTL
    )
    {
        // Validate request
        $client = $this->validateClient($request);
        $user = $this->validateUser($request, $client);
        $scopes = $this->validateScopes($this->getRequestParameter('scope', $request, $this->defaultScope));

        if (!($allowedScopes = $this->allowedUserScopes($user, $scopes))) {
            OAuthServerException::scopeDenied();
        }

        // Finalize the requested scopes
        $finalizedScopes = $this->scopeRepository->finalizeScopes($allowedScopes, $this->getIdentifier(), $client, $user->getIdentifier());

        // Issue and persist new access token
        $accessToken = $this->issueAccessToken($accessTokenTTL, $client, $user->getIdentifier(), $finalizedScopes);
        $this->getEmitter()->emit(new RequestEvent(RequestEvent::ACCESS_TOKEN_ISSUED, $request));
        $responseType->setAccessToken($accessToken);

        // Issue and persist new refresh token if given
        $refreshToken = $this->issueRefreshToken($accessToken);

        if ($refreshToken !== null) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::REFRESH_TOKEN_ISSUED, $request));
            $responseType->setRefreshToken($refreshToken);
        }

        return $responseType;
    }

    /**
     *
     *
     * @param User $user
     * @param $scopes
     */
    protected function allowedUserScopes($user, $scopes)
    {
        $availableScopes = $user->user()->availableScopes();

        if ($availableScopes === true) {
            return $scopes;
        } else {
            $scopes = collect($scopes);
            if ($scopes->count() == 1 && $scopes->first()->getIdentifier() == '*') {
                return collect(Passport::scopes())->whereIn('id', $availableScopes)->pluck('id')
                    ->mapInto(\Laravel\Passport\Bridge\Scope::class)->toArray();
            }
            $blocked = $scopes->whereNotIn('getIdentifier', $availableScopes);
            return $blocked->isEmpty() ? $scopes->whereIn('getIdentifier', $availableScopes)->toArray() : null;
        }
    }
}
