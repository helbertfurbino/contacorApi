<?php

namespace Cora\Base;

use GuzzleHttp\Client;
use Ramsey\Uuid\Uuid;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Symfony\Contracts\Cache\ItemInterface;

class ApiCoraBase
{
	public $token;
	public $clientId;
	protected $certFile;
	protected $privateKey;
	protected $cacheKey;
	protected $idempotencyKey;
	protected $cache;

	const URL_BASE_CORA = 'https://matls-clients.api.cora.com.br/';
	const TOKEN_GRANT_TYPE = 'client_credentials';
	const DEFAULT_CACHE_KEY = 'cora_api_token';
	const CACHE_TIME = 3600; // Tempo padrão em segundos

	/**
	 * Construtor da classe.
	 *
	 * @param string      $certFile        Caminho para o certificado SSL.
	 * @param string      $privateKey      Caminho para a chave privada.
	 * @param string      $clientId        ID do cliente.
	 * @param string|null $cacheKey        Chave opcional para o cache.
	 * @param string|null $cacheDirectory  Diretório opcional para armazenar o cache.
	 */
	public function __construct($certFile, $privateKey, $clientId, $cacheKey = null, $cacheDirectory = null)
	{
		if (empty($certFile) || empty($privateKey) || empty($clientId)) {
			throw new \InvalidArgumentException('CertFile, PrivateKey e ClientId são obrigatórios.');
		}

		$this->certFile = $certFile;
		$this->privateKey = $privateKey;
		$this->clientId = $clientId;
		$this->cacheKey = $cacheKey ?: self::DEFAULT_CACHE_KEY;

		// Define o diretório de cache padrão se não for fornecido
		$cacheDir = $cacheDirectory ?: sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'api_cora_cache';

		// Inicializa o adaptador de cache
		$this->cache = new FilesystemAdapter(
			namespace: '',
			defaultLifetime: 0, // Define a expiração individualmente
			directory: $cacheDir // Diretório de cache configurável
		);

		// Garante que o diretório de cache exista
		if (!is_dir($cacheDir)) {
			if (!mkdir($cacheDir, 0755, true) && !is_dir($cacheDir)) {
				throw new \RuntimeException(sprintf('Diretório de cache "%s" não pode ser criado.', $cacheDir));
			}
		}

		$this->token = $this->getCachedToken();
	}

	/**
	 * Obtém o token cacheado ou busca um novo se expirado ou inexistente.
	 *
	 * @return string Token de acesso.
	 */
	private function getCachedToken()
	{
		return $this->cache->get($this->cacheKey, function (ItemInterface $item) {
			// Define o tempo de expiração do cache baseado em CACHE_TIME ou no 'expires_in' da API
			$item->expiresAfter(self::CACHE_TIME);
			return $this->fetchNewToken();
		});
	}

	/**
	 * Busca um novo token da API Cora.
	 *
	 * @return string Novo token de acesso.
	 *
	 * @throws \RuntimeException Se houver falha na comunicação ou na resposta da API.
	 */
	private function fetchNewToken()
	{
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
		if ($response === false) {
			$error = curl_error($ch);
			curl_close($ch);
			throw new \RuntimeException('Falha ao comunicar com a API Cora: ' . $error);
		}

		$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
		curl_close($ch);

		if ($httpCode !== 200) {
			throw new \RuntimeException('API Cora retornou código HTTP ' . $httpCode . ': ' . $response);
		}

		$data = json_decode($response, true);
		if (json_last_error() !== JSON_ERROR_NONE) {
			throw new \RuntimeException('Erro ao decodificar a resposta da API.');
		}

		if (isset($data['access_token'])) {
			$this->token = $data['access_token'];
			$expiresInSeconds = isset($data['expires_in']) ? (int)$data['expires_in'] : self::CACHE_TIME;

			// Retorna o token para ser armazenado no cache com a expiração definida
			return $this->token;
		} else {
			throw new \RuntimeException('Erro ao obter o token de acesso: ' . json_encode($data));
		}
	}

	/**
	 * Obtém um cliente Guzzle configurado com as credenciais e headers necessários.
	 *
	 * @param string|null $idempotencyKey Chave de idempotência opcional.
	 * @return Client Cliente Guzzle configurado.
	 */
	public function getClient($idempotencyKey = null)
	{
		$this->idempotencyKey = $idempotencyKey ?: Uuid::uuid4()->toString();

		return new Client([
			'base_uri' => self::URL_BASE_CORA,
			'cert' => $this->certFile,
			'ssl_key' => $this->privateKey,
			'headers' => $this->getHeaders(),
		]);
	}

	/**
	 * Gera os headers necessários para as requisições à API Cora.
	 *
	 * @return array Headers para a requisição.
	 *
	 * @throws \RuntimeException Se o token não estiver disponível.
	 */
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
