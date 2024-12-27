<?php

namespace Cora\Base;

use DateTime;
use GuzzleHttp\Client;
use Ramsey\Uuid\Uuid;

class ApiCoraBase
{
	public $token;
	public $clientId;
	protected $certFile;
	protected $privateKey;
	protected $cacheKey;
	protected $idempotencyKey;

	const URL_BASE_CORA = 'https://matls-clients.api.cora.com.br/';
	const TOKEN_GRANT_TYPE = 'client_credentials';
	const DEFAULT_CACHE_KEY = 'cora_api_token';
	const CACHE_TIME = 3600;

	public function __construct($certFile, $privateKey, $clientId, $cacheKey = null)
	{
		if (empty($certFile) || empty($privateKey) || empty($clientId)) {
			throw new \InvalidArgumentException('CertFile, PrivateKey e ClientId são obrigatórios.');
		}

		$this->certFile = $certFile;
		$this->privateKey = $privateKey;
		$this->clientId = $clientId;
		$this->cacheKey = $cacheKey ?: self::DEFAULT_CACHE_KEY;

		$this->token = $this->getCachedToken();
	}

	private function getCachedToken()
	{
		$cacheFile = 'token_cache.txt';
		$cacheTime = self::CACHE_TIME;

		if (file_exists($cacheFile) && time() - $cacheTime < filemtime($cacheFile)) {
			$cachedToken = file_get_contents($cacheFile);
			return $cachedToken;
		}

		$newToken = $this->fetchNewToken();
		file_put_contents($cacheFile, $newToken);
		return $newToken;
	}
	private function fetchNewToken()
	{
		try {
			$url = self::URL_BASE_CORA . "token";
			$ch = curl_init($url);

			curl_setopt($ch, CURLOPT_SSLKEY, $this->privateKey);
			curl_setopt($ch, CURLOPT_SSLCERT, $this->certFile);
			curl_setopt($ch, CURLOPT_HTTPHEADER, ["Content-Type: application/x-www-form-urlencoded"]);
			curl_setopt($ch, CURLOPT_POST, true);
			curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
				'grant_type' => self::TOKEN_GRANT_TYPE,
				'client_id' => $this->clientId
			]));
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

			$response = curl_exec($ch);
			curl_close($ch);

			if ($response === false) {
				$error = curl_error($ch);
				throw new \RuntimeException('Falha ao comunicar com a API Cora: ' . $error);
			}

			$data = json_decode($response, true);
			if (json_last_error() !== JSON_ERROR_NONE) {
				throw new \RuntimeException('Erro ao decodificar a resposta da API.');
			}

			if (isset($data['access_token'])) {
				$this->token = $data['access_token'];
				$expiresInSeconds = $data['expires_in'] ?? self::CACHE_TIME;
				$this->setCache($this->cacheKey, $this->token, (new DateTime())->modify('+' . $expiresInSeconds . ' seconds'));


				return $this->token;
			} else {
				throw new \RuntimeException('Erro ao obter o token de acesso: ' . json_encode($data));
			}
		} catch (\Throwable $th) {
			throw new \RuntimeException('Erro ao obter token de acesso: ' . $th->getMessage());
		}
	}

	private function setCache($key, $value, $ttl)
	{
		$cacheFile =  $key;
		file_put_contents($cacheFile, $value);
		touch($cacheFile, time() + $ttl);
	}

	public function getClient($idempotencyKey = null)
	{
		$myuuid = Uuid::uuid4();

		$this->idempotencyKey = $idempotencyKey ?: $myuuid->toString();

		return new Client([
			'base_uri' => self::URL_BASE_CORA,
			'cert' => $this->certFile,
			'ssl_key' => $this->privateKey,
			'headers' => $this->getHeaders(),
		]);
	}

	public function getHeaders()
	{
		if (!$this->token) {
			throw new \RuntimeException('Token não encontrado. Impossível gerar headers de autorização.');
		}

		return [
			'Idempotency-Key' => $this->idempotencyKey,
			'Authorization' => 'Bearer ' . $this->token,
			'Content-Type' => 'application/json',
		];
	}
}
