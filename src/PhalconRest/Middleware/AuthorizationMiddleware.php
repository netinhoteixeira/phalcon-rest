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
        } else {
            // DONE: 2019-12-29 04:51 Francisco - Sometimes the value is not right fetched
            $authHeader = $this->request->getHeader('AUTHORIZATION');
            $authQuery = $this->request->getQuery('token');

            if ((is_null($authHeader)) || (empty($authHeader))) {
                $di = FactoryDefault::getDefault();
                $request = $di->get(Services::REQUEST);

                $headers = $request->getHeaders();

                if (array_key_exists('Authorization', $headers)) {
                    $authHeader = $headers['Authorization'];
                }
            }

            $token = $authQuery ? $authQuery : $this->parseBearerValue($authHeader);

            if ($token) {
                $this->authManager->authenticateToken($token);
            }
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
}