<?php

namespace PhalconRest\Middleware;

use PhalconApi\Constants\Services;
use Phalcon\Events\Event;
use Phalcon\Mvc\Micro;
use Phalcon\Mvc\Micro\MiddlewareInterface;
use PhalconRest\Mvc\Plugin;
use PhalconRest\Api;
use PhalconApi\Constants\ErrorCodes;
use PhalconApi\Exception;

class AuthorizationMiddleware extends Plugin implements MiddlewareInterface
{

    public function beforeExecuteRoute(Event $event, Api $api)
    {
        $collection = $api->getMatchedCollection();
        $endpoint = $api->getMatchedEndpoint();

        if (!$collection || !$endpoint) {
            return;
        }

        // DONE: 2019-12-29 02:41 Francisco - This kind of middleware is not called twice anymore,
        // so AuthenticationMiddleware does not working
        $token = $this->request->getToken();
        if ($token) {
            $this->authManager->authenticateToken($token);
        }

        $allowed = $this->acl->isAllowed($this->userService->getRole(), $collection->getIdentifier(),
            $endpoint->getIdentifier());

        if (!$allowed) {
            throw new Exception(ErrorCodes::ACCESS_DENIED);
        }
    }

    public function call(Micro $api)
    {
        return true;
    }

    protected function parseBearerValue($string)
    {
        if (strpos(trim($string), 'Bearer') !== 0) {
            return null;
        }

        return preg_replace('/.*\s/', '', $string);
    }

}