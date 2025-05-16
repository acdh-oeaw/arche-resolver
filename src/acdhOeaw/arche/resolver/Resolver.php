<?php

/*
 * The MIT License
 *
 * Copyright 2017 Austrian Centre for Digital Humanities.
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

use PDO;
use PDOException;
use RuntimeException;
use Throwable;
use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Exception\RequestException;
use termTemplates\PredicateTemplate as PT;
use acdhOeaw\arche\lib\Repo;
use acdhOeaw\arche\lib\RepoDb;
use acdhOeaw\arche\lib\Schema;
use acdhOeaw\arche\lib\SearchConfig;
use acdhOeaw\arche\lib\exception\NotFound;
use acdhOeaw\arche\lib\exception\AmbiguousMatch;
use acdhOeaw\arche\lib\disserv\RepoResourceInterface;
use acdhOeaw\arche\lib\disserv\dissemination\ServiceInterface;
use acdhOeaw\arche\lib\disserv\RepoResource;
use acdhOeaw\arche\lib\disserv\RepoResourceDb;
use zozlak\HttpAccept;
use zozlak\logging\Log;

/**
 * Resolves an URI being defined as an identifier of a repository object to
 * the proper dissemination method.
 *
 * @author zozlak
 */
class Resolver {

    const FORMAT_LIST_SERVICES = '__list__';
    const FORMAT_QUERY_PARAM   = 'format';

    static public bool $debug = false;
    private object $config;
    private Log $log;

    public function __construct(object $config) {
        $this->config = $config;

        $lc        = $this->config->resolver->logging;
        $this->log = new Log($lc->file, $lc->level);
    }

    /**
     * Performs the resolution
     */
    public function resolve(): void {
        try {
            $resId = $this->getResourceId();
            $res   = $this->findResource($resId);

            $cmdiNmsp = $this->config->resolver->cmdi->idNamespace;
            $isCmdi   = substr($resId, 0, strlen($cmdiNmsp)) === $cmdiNmsp;
            $accept   = $this->sanitizeAcceptHeader($isCmdi);
            if ($accept === self::FORMAT_LIST_SERVICES) {
                $this->listDissServices($res);
                return;
            }

            // check fast resolution track (a basic "match on mime and append a suffix to the resource URL" model)
            $done = $this->checkFastTrack($res);
            if ($done) {
                return;
            }

            $service = $this->findDissService($res);
            if ($service === null) {
                $this->redirect($res->getUri());
            } elseif (!$service->getRevProxy()) {
                $request = $service->getRequest($res);
                $this->redirect($request->getUri());
            } else {
                // It's the only thing we can check for sure cause other resources 
                // might be encoded in the diss service request in a way the resolver
                // doesn't understand.
                // In the "reverse proxy to separated location having full repo access
                // rights" scenario it creates problem of "resource injection"
                // attacks when a dissemination service parameter (which access rights
                // aren't checked by the resolver) will be manipulated to get access
                // to it.
                $this->checkAccessRights($res->getUri());

                $request = $service->getRequest($res);
                $this->log->info("\tmaking a proxy request to " . $request->getUri());
                Proxy::proxy($request);
            }
        } catch (Throwable $e) {
            $this->log->error($e);
            http_response_code($e->getCode() >= 400 ? $e->getCode() : 500);
        }
    }

    /**
     * Returns id of a resource to be resolved (based on the HTTP request).
     * 
     * @return string
     */
    private function getResourceId(): string {
        $https = filter_input(\INPUT_SERVER, 'HTTPS');
        if (strtolower(filter_input(\INPUT_SERVER, 'HTTP_X_FORWARDED_PROTO')) === 'https') {
            $https = 'https';
        }
        $port = filter_input(\INPUT_SERVER, 'SERVER_PORT');
        if (filter_input(\INPUT_SERVER, 'HTTP_X_FORWARDED_PORT')) {
            $port = filter_input(\INPUT_SERVER, 'HTTP_X_FORWARDED_PORT');
        }
        $proto = ((int) $port) === 443 || !empty($https) && $https !== 'off' ? 'https' : 'http';
        if (!empty($this->config->resolver->idHost)) {
            $proto = $this->config->resolver->idProtocol;
        }

        if (filter_input(\INPUT_SERVER, 'HTTP_X_FORWARDED_HOST')) {
            $host = explode(',', filter_input(\INPUT_SERVER, 'HTTP_X_FORWARDED_HOST'));
            $host = trim($host[0]);
        } else {
            $host = filter_input(\INPUT_SERVER, 'HTTP_HOST');
        }
        if (!empty($this->config->resolver->idHost)) {
            $host = $this->config->resolver->idHost;
        }

        $path = filter_input(\INPUT_SERVER, 'REDIRECT_URL');
        $path = substr($path, strlen($this->config->resolver->idPathBase));

        $resId    = $proto . '://' . $host . $path;
        $extResId = filter_input(\INPUT_GET, 'id');
        if (!empty($extResId)) {
            $resId = $extResId;
        }

        $this->log->info("Resolving $resId");
        return $resId;
    }

    /**
     * Finds a repository resource which corresponds to a given URI
     * @param string $resId URI to be mapped to a repository resource
     * @return RepoResourceInterface
     * @throws RuntimeException
     */
    private function findResource(string $resId): RepoResourceInterface {
        $schema  = new Schema($this->config->schema);
        $headers = new Schema($this->config->rest->headers);
        foreach ($this->config->resolver->repositories as $r) {
            try {
                /* @var $repo \acdhOeaw\acdhRepoLib\RepoInterface */
                if (!empty($r->dbConnStr ?? '')) {
                    $pdo   = new PDO($r->dbConnStr);
                    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
                    $repo  = new RepoDb($r->baseUrl, $schema, $headers, $pdo);
                    $class = RepoResourceDb::class;
                    ;
                } else {
                    $repo  = new Repo($r->baseUrl, (array) ($r->options ?? []));
                    $class = RepoResource::class;
                }
                $repo->setQueryLog($this->log);

                $cfg               = new SearchConfig();
                $cfg->metadataMode = '0_0_0_0';
                $cfg->class        = $class;
                /** @var \acdhOeaw\arche\lib\disserv\RepoResource $res */
                $res               = $repo->getResourceById($resId, $cfg);
                $this->log->info("\tresource found: " . $res->getUri());
                return $res;
            } catch (NotFound $e) {
                // skip as maybe it will match the next repository
            } catch (AmbiguousMatch $e) {
                throw new RuntimeException('Internal Server Error - many resources with the given URI', 500);
            } catch (RequestException $e) {
                // simply skip faulty repositories
            } catch (PDOException $e) {
                // simply skip faulty repositories
            }
        }
        throw new NotFound();
    }

    /**
     * Sanitizes requested output format by applying following rules:
     * - `format` request query parameter overwrites whole HTTP Accept header
     * - the wildcard is turned into the default dissemination service
     * - for a CMDI requests format mappings defined in cfg.resolver.cmdi.formatMappings
     *   are applied
     * 
     * @param bool $isCmdi is CMDI id requested?
     * @return string sanitized Accept header value
     */
    private function sanitizeAcceptHeader(bool $isCmdi): string {
        $accept = filter_input(\INPUT_SERVER, 'HTTP_ACCEPT');

        $forceFormat = filter_input(\INPUT_GET, self::FORMAT_QUERY_PARAM);
        if (!empty($forceFormat)) {
            $accept = $forceFormat;
        }

        $default = $this->config->resolver->defaultDissService;
        $accept  = preg_replace('|[*]/[*](;q=[.0-9]+)?|', $default . '\1', $accept);

        $_SERVER['HTTP_ACCEPT'] = $accept;
        $this->log->info("\trequested format: " . $accept);

        if ($isCmdi) {
            $cmdiMap     = $this->config->resolver->cmdi->formatMappings;
            $cmdiDefault = $this->config->resolver->cmdi->defaultDissService;
            try {
                $bestMatch = HttpAccept::getBestMatch(array_keys((array) $cmdiMap))->getFullType();
                $accept    = isset($cmdiMap->$bestMatch) ? $cmdiMap->$bestMatch : $cmdiDefault;
            } catch (RuntimeException $e) {
                $accept = $cmdiDefault;
            }
            $_SERVER['HTTP_ACCEPT'] = $accept;
            HttpAccept::parse();
            $this->log->info("\tCMDI format mapped to $accept");
        }

        return $accept;
    }

    /**
     * Checks a fast resolution track "match on mime and appent a suffix to the resource URL".
     * 
     * The list of {mime type, URL suffix} pairs is read from the config.
     * 
     * @param RepoResourceInterface $res repository resource to be disseminated
     * @return bool
     */
    private function checkFastTrack(RepoResourceInterface $res): bool {
        $formats  = [];
        $suffixes = [];
        foreach ($this->config->resolver->fastTrack as $mime => $suffix) {
            $format                           = new HttpAccept($mime);
            $formats[]                        = $format;
            $suffixes[$format->getFullType()] = $suffix;
        }
        try {
            $bestMatch = HttpAccept::getBestMatch($formats);
            if ($bestMatch->getQuality() == 1 || count(HttpAccept::get()) === 1) {
                $url = $res->getUri() . $suffixes[$bestMatch->getFullType()];
                $this->log->info("\tfast track found for $bestMatch: $url");
                $this->redirect($url . '?' . http_build_query($_GET));
                return true;
            } else {
                $this->log->info("\tfast track $bestMatch found but skipped due to low weight");
            }
        } catch (RuntimeException $e) {
            
        }
        return false;
    }

    /**
     * 
     * @param RepoResourceInterface $res
     * @return ?ServiceInterface
     */
    private function findDissService(RepoResourceInterface $res): ?ServiceInterface {
        /* @var $service \acdhOeaw\arche\lib\disserv\dissemination\ServiceInterface */
        $service  = null;
        $dissServ = $res->getDissServices();
        $formats  = array_map(function ($x) {
            return (new HttpAccept($x))->getFullType();
        }, array_keys($dissServ));
        $dissServ = array_combine($formats, $dissServ);
        $this->log->info("\tavailable diss services: " . implode(', ', $formats));

        try {
            $bestMatch = HttpAccept::getBestMatch(array_keys($dissServ));
            $_GET[self::FORMAT_QUERY_PARAM] = $bestMatch;
            $service   = $dissServ[$bestMatch->getFullType()];
            $this->log->info("\tmatched $bestMatch");
        } catch (RuntimeException $e) {
            $defaultServ = $this->config->resolver->defaultDissService;
            $defaultServ = (new HttpAccept($defaultServ))->getFullType();
            if (isset($dissServ[$defaultServ])) {
                $service = $dissServ[$defaultServ];
                $this->log->info("\tassigned default $defaultServ");
            }
        }
        return $service;
    }

    /**
     * Checks if a client is able to access a given URI.
     * @param string $uri URI to be checked
     * @throws AccessRightsException
     * @throws RequestException
     */
    private function checkAccessRights(string $uri): void {
        $headers = Proxy::getForwardHeaders();
        $request = new Request('HEAD', $uri, $headers);
        $options = [
            'verify'          => false,
            'allow_redirects' => true,
        ];
        $client  = new Client($options);
        try {
            $client->send($request);
        } catch (RequestException $e) {
            if ($e->hasResponse()) {
                $code = $e->getResponse()?->getStatusCode();
                if ($code === 401) {
                    header('HTTP/1.1 401 Unauthorized');
                    header('WWW-Authenticate: Basic realm="resolver"');
                    echo "Authentication required\n";
                    throw new AccessRightsException($e->getMessage(), $code);
                } elseif ($code === 403) {
                    header('HTTP/1.1 403 Forbidden');
                    echo "Access denied\n";
                    throw new AccessRightsException($e->getMessage(), $code);
                }
            }
            throw $e;
        }
    }

    private function redirect(string $url): void {
        header('Location: ' . $url);
        $this->log->info("\tredirecting to $url");
    }

    private function listDissServices(RepoResourceInterface $res): void {
        /* @var $service \acdhOeaw\arche\disserv\dissemination\ServiceInterface */
        $services = $res->getDissServices();
        $results  = [];
        foreach ($services as $format => $service) {
            $results[] = [
                'serviceUri'  => $service->getUri(),
                'formats'     => $service->getFormats(),
                'url'         => $service->getRevProxy() ? "reverse proxy" : (string) $service->getRequest($res)->getUri(),
                'description' => (string) $service->getGraph()->getObject(new PT($this->config->schema->label)),
            ];
        }
        header('Content-Type: application/json');
        echo json_encode($results, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
}
