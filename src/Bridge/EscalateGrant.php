<?php

namespace Laravel\Passport\Bridge;

use Laravel\Passport\Exceptions\OAuthServerException;
use Laravel\Passport\Passport;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;

class EscalateGrant extends RefreshTokenGrant
{
    use ValidateUsersScopes;

    /**
     * EnhanceGrant constructor.
     * @param RefreshTokenRepositoryInterface $refreshTokenRepository
     * @param UserRepositoryInterface $userRepositor
     */
    public function __construct(RefreshTokenRepositoryInterface $refreshTokenRepository, UserRepositoryInterface $userRepository)
    {
        $this->setUserRepository($userRepository);
        parent::__construct($refreshTokenRepository);
    }

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
        $oldRefreshToken = $this->validateOldRefreshToken($request, $client->getIdentifier());
        $user = $this->getUser($oldRefreshToken['user_id'], $client);

        $requestedScopes = $this->getRequestParameter('scope', $request);

        if($requestedScopes === null) {
            throw OAuthServerException::scopeDenied();
        }

        $scopes = $this->validateScopes($requestedScopes);

        if (!($allowedScopes = $this->validateUserScopes($user, $scopes))) {
            OAuthServerException::scopeDenied();
        }

        // Finalize the requested scopes
        $finalizedScopes = $this->scopeRepository->finalizeScopes($allowedScopes, $this->getIdentifier(), $client, $user->getIdentifier());

        // Expire old tokens
        $this->accessTokenRepository->revokeAccessToken($oldRefreshToken['access_token_id']);
        $this->refreshTokenRepository->revokeRefreshToken($oldRefreshToken['refresh_token_id']);

        // Issue and persist new access token
        $accessToken = $this->issueAccessToken($accessTokenTTL, $client, $oldRefreshToken['user_id'], $finalizedScopes);
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

    private function getUser($id, ClientEntityInterface $client)
    {
        $user = $this->userRepository->getUserEntityById(
            $id,
            $this->getIdentifier(),
            $client
        );

        if ($user instanceof UserEntityInterface === false) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::USER_AUTHENTICATION_FAILED, $request));

            throw OAuthServerException::invalidGrant();
        }

        return $user;
    }

    /**
     * {@inheritdoc}
     */
    public function getIdentifier()
    {
        return 'escalate';
    }
}
