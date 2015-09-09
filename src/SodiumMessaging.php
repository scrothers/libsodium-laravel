<?php

namespace scrothers\laravelsodium;

class SodiumMessaging
{
    /**
     * Returns a set of new keys, useful for generating keys for a user.
     *
     * @return array
     */
    public function newKeys()
    {
        $signKey = SodiumLibrary::genSignKeypair();
        $encrKey = SodiumLibrary::genBoxKeypair();

        return [
            'sign_pub' => $signKey['pub'],
            'sign_pri' => $signKey['pri'],
            'encr_pub' => $encrKey['pub'],
            'encr_pri' => $encrKey['pri'],
        ];
    }

    /**
     * Send an encrypted message to a public key.
     *
     * @param string $sender_private  Sending user's private encryption key.
     * @param string $receiver_public Receiving user's public encryption key.
     * @param string $message         Message to be sent.
     *
     * @return string
     */
    public function sendMessage($sender_private, $receiver_public, $message)
    {
        return SodiumLibrary::messageSendEncrypt($receiver_public, $sender_private, $message);
    }

    /**
     * Sign a message for authenticity.
     *
     * @param string $sender_private Sending user's private signing key.
     * @param string $message        Message to sign.
     *
     * @return mixed
     */
    public function signMessage($sender_private, $message)
    {
        return SodiumLibrary::signMessage($sender_private, $message);
    }

    /**
     * Encrypt and sign a message to be sent.
     *
     * @param string $sender_encr_private Sending user's private encryption key.
     * @param string $sender_sign_private Sending user's private signing key.
     * @param string $receiver_public     Receiving user's public encryption key.
     * @param string $message             Message to be sent and signed.
     *
     * @return mixed
     */
    public function sendSignMessage($sender_encr_private, $sender_sign_private, $receiver_public, $message)
    {
        return $this->signMessage($sender_sign_private, $this->sendMessage($sender_encr_private, $receiver_public, $message));
    }

    /**
     * Receive and decrypt a message from a user.
     *
     * @param string $sender_encr_public    Sending user's public encryption key.
     * @param string $receiver_encr_private Receiving user's private encryption key.
     * @param string $message               Message to be decrypted and read.
     *
     * @return mixed
     */
    public function readMessage($sender_encr_public, $receiver_encr_private, $message)
    {
        return SodiumLibrary::messageReceiveEncrypt($receiver_encr_private, $sender_encr_public, $message);
    }

    /**
     * Verify a signature and read a message.
     *
     * @param string $sender_sign_public Sending user's public signing key.
     * @param string $message            Message to be decrypted and read.
     *
     * @return mixed
     */
    public function verifyMessage($sender_sign_public, $message)
    {
        return SodiumLibrary::verifySignature($sender_sign_public, $message);
    }

    /**
     * Verify a signature and decrypt a message.
     *
     * @param string $sender_encr_public    Sending user's public encryption key.
     * @param string $sender_sign_public    Sending user's public signing key.
     * @param string $receiver_encr_private Receiving user's private encryption key.
     * @param string $message               Message to be decrypted and read.
     *
     * @return mixed
     */
    public function verifyReadMessage($sender_encr_public, $sender_sign_public, $receiver_encr_private, $message)
    {
        return $this->readMessage($sender_encr_public, $receiver_encr_private, $this->verifyMessage($sender_sign_public, $message));
    }
}