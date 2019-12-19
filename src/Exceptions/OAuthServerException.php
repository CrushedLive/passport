<?php

namespace Laravel\Passport\Exceptions;

use Exception;
use Illuminate\Http\Response;
use League\OAuth2\Server\Exception\OAuthServerException as LeagueException;

class OAuthServerException extends Exception
{
    /**
     * The response to render.
     *
     * @var \Illuminate\Http\Response
     */
    protected $response;

    /**
     * Create a new OAuthServerException.
     *
     * @param  \League\OAuth2\Server\Exception\OAuthServerException  $e
     * @param  \Illuminate\Http\Response  $response
     * @return void
     */
    public function __construct(LeagueException $e, Response $response)
    {
        parent::__construct($e->getMessage(), $e->getCode(), $e);

        $this->response = $response;
    }

    /**
     * Render the exception into an HTTP response.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function render($request)
    {
        return $this->response;
    }

    /**
     * Invalid scope error.
     *
     * @param null|string $redirectUri A HTTP URI to redirect the user back to
     *
     * @return \League\OAuth2\Server\Exception\OAuthServerException
     */
    public static function scopeDenied()
    {
        $errorMessage = 'The requested scope is not available to this grant';
        $hint = 'Please check and apply the appropriate scopes to the grant';

        return new static($errorMessage, 5, 'invalid_scope', 400, $hint);
    }
}
