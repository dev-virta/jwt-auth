<?php

namespace Tymon\JWTAuth\Providers\JWT;

use Exception;
use Namshi\JOSE\JWS;
use Namshi\JOSE\Base64\Base64Encoder;
use Namshi\JOSE\Base64\Base64UrlSafeEncoder;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;

class NamshiAdapter extends JWTProvider implements JWTInterface
{
    /**
     * @var \Namshi\JOSE\JWS
     */
    protected $jws;

    public function __construct($secret, $algo, $driver = null)
    {
        parent::__construct($secret, $algo);

        $this->jws = $driver ?: new JWS(['typ' => 'JWT', 'alg' => $algo]);
    }

    /**
     * Create a JSON Web Token
     *
     * @return string
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    public function encode(array $payload)
    {
        try {
            $this->jws->setPayload($payload)->sign($this->secret);

            return $this->jws->getTokenString();
        } catch (Exception $e) {
            throw new JWTException('Could not create token: ' . $e->getMessage());
        }
    }

    /**
     * Decode a JSON Web Token
     *
     * @param  string  $token
     * @return array
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    public function decode($token)
    {
        try {
            $jws = JWS::load($token);
        } catch (Exception $e) {
            throw new TokenInvalidException('Could not decode token: ' . $e->getMessage());
        }

        if (!$jws->verify($this->secret, $this->algo) && !$this->verifyJWSWithDeprecatedMethod($jws, $token, $this->secret)) {
            throw new TokenInvalidException('Token Signature could not be verified.');
        }

        return $jws->getPayload();
    }

    /**
     * Verify the JWS token with the old method
     *
     * @param  JWS  $jws
     * @param  string $token
     * @param  string $key
     * @return bool
     */
    private function verifyJWSWithDeprecatedMethod($jws, $token, $key)
    {
        $encoder = $this->getEncoderFromToken($token);
        $decodedSignature = $encoder->decode($jws->getEncodedSignature());
        $signinInput = $this->getSigninInput($jws, $token);
        $test = $jws->getSigninInput();

        // Signed the input using deprecated method
        $signedInput = hash_hmac('sha256', $signinInput, (string) $key);

        return hash_equals($signedInput, $decodedSignature);
    }

    /**
     * Get the original token signin input if it exists, otherwise generate the
     * signin input for the current JWS
     *
     * @param JWS $jws
     * @return string
     */
    private function getSigninInput($jws, $token)
    {
        $parts = explode('.', $token);

        if (count($parts) >= 2) {
            return sprintf('%s.%s', $parts[0], $parts[1]);
        }

        return $jws->generateSigninInput();
    }

    /**
     * Decode a JSON Web Token
     *
     * @param  string  $token
     * @return array
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    private function getEncoderFromToken($token)
    {
        return strpbrk($token, '+/=') ? new Base64Encoder() : new Base64UrlSafeEncoder();
    }
}
