<?php

/*
 * The MIT License
 *
 * Copyright 2018 Austrian Centre for Digital Humanities.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

namespace acdhOeaw\arche\resolver;

use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Uri;
use Psr\Http\Message\ResponseInterface;
use GuzzleHttp\Exception\RequestException;

/**
 * Simple reverse proxy implementation for dissemination services.
 *
 * @author zozlak
 */
class Proxy {

    /**
     * Response headers not to be forwarded to the client.
     * (https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers#hbh plus host header)
     * @var array<string>
     */
    static $skipResponseHeaders = [
        'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
        'te', 'trailer', 'transfer-encoding', 'upgrade', 'host'
    ];

    /**
     * Client request headers not to be forwarded to the diss service.
     * @var array<string>
     */
    static $skipForwardHeaders = ['host'];

    /**
     * Returns all valid headers comming from the client request.
     * @return array<string, string>
     */
    static public function getForwardHeaders(): array {
        $headers = array();
        foreach ($_SERVER as $k => $v) {
            if (substr($k, 0, 5) !== 'HTTP_') {
                continue;
            }
            $k = str_replace('_', '-', strtolower(substr($k, 5)));
            if (!in_array($k, self::$skipForwardHeaders)) {
                $headers[$k] = $v;
            }
        }

        $contentType = filter_input(\INPUT_SERVER, 'CONTENT_TYPE');
        if ($contentType !== null) {
            $headers['content-type'] = $contentType;
        }

        $contentLength = filter_input(\INPUT_SERVER, 'CONTENT_LENGTH');
        if ($contentLength !== null) {
            $headers['content-length'] = $contentLength;
        }

        $cookies = array();
        foreach ($_COOKIE as $k => $v) {
            $cookies[] = $k . '=' . $v;
        }
        if (count($cookies) > 0) {
            $headers['cookie'] = implode('; ', $cookies);
        }

        if (isset($_SERVER['PHP_AUTH_USER'])) {
            $headers['Authorization'] = 'Basic ' . base64_encode($_SERVER['PHP_AUTH_USER'] . ':' . ($_SERVER['PHP_AUTH_PW'] ?? ''));
        }

        return $headers;
    }

    /**
     * Does the job:
     * 
     * - takes a diss service request
     * - adds all headers provided by the client request to it (most importantly Authentication)
     * - recursively issues a HEAD request to the diss service URL to resolve all redirects
     * - makes a final request passing client request body to the diss service
     *   and passing data returned by the diss service to the client
     * @param Request $request diss service request to be reverse-proxied
     * @return ?ResponseInterface
     * @throws RequestException
     */
    static public function proxy(Request $request): ?ResponseInterface {
        $headers       = $request->getHeaders();
        $clientHeaders = self::getForwardHeaders();
        foreach ($clientHeaders as $h => $v) {
            if (!isset($headers[$h])) {
                $headers[$h] = [];
            }
            if (!is_array($headers[$h])) {
                $headers[$h] = [$headers[$h]];
            }
            $headers[$h][] = $v;
        }

        $options                    = [];
        $options['verify']          = false;
        $options['allow_redirects'] = false;
        $client                     = new Client($options);

        // Process possible redirects
        $head = new Request($request->getMethod(), $request->getUri(), $headers, $request->getBody());
        while (true) {
            $response = self::sendRequest($client, $head);
            $code     = $response?->getStatusCode();
            if ((int) ($code / 100) === 3 && $code <= 307) {
                $head = $head->withUri(new Uri($response->getHeader('Location')[0]));
            } else {
                break;
            }
        }
        $request = $request->withUri($head->getUri());

        // adjust client options
        $output                = fopen('php://output', 'w');
        $options['sink']       = $output;
        $options['on_headers'] = function (Response $r) {
            self::handleResponseHeaders($r);
        };
        $client = new Client($options);

        // make a final proxy call
        try {
            $response = $client->send($request);
        } catch (RequestException $e) {
            if (!$e->hasResponse()) {
                throw $e; // if there is no response we can't properly return from function
            }
            $response = $e->getResponse();
        } finally {
            if (is_resource($output)) {
                fclose($output);
            }
        }
        return $response;
    }

    /**
     * Handles response headers.
     * @param Response $response
     */
    static public function handleResponseHeaders(Response $response): void {
        $status = $response->getStatusCode();
        if (in_array($status, array(401, 403))) {
            if (!isset($_SERVER['PHP_AUTH_USER'])) {
                http_response_code(401);
                header('WWW-Authenticate: Basic realm="resolver"');
            }
            return;
        } else {
            http_response_code($response->getStatusCode());
            foreach ($response->getHeaders() as $name => $values) {
                if (in_array(strtolower($name), self::$skipResponseHeaders)) {
                    continue;
                }
                foreach ($values as $value) {
                    header(sprintf('%s: %s', $name, $value), false);
                }
            }
        }
    }

    /**
     * Sends a given request
     * @param Client $client Guzzle HTTP client object
     * @param Request $request request to be sent
     * @return ?ResponseInterface
     * @throws RequestException
     */
    static private function sendRequest(Client $client, Request $request): ?ResponseInterface {
        try {
            $response = $client->send($request);
        } catch (RequestException $e) {
            if (!$e->hasResponse()) {
                throw $e; // if there is no response we can't properly return from function
            }
            $response = $e->getResponse();
        } finally {
            if ($request->getBody()->getSize()) {
                $request->getBody()->close();
            }
        }
        return $response;
    }
}
