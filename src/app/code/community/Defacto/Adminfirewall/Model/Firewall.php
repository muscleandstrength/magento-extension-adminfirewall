<?php

/**
 * @method string[] getWhitelist() string array of ip addresses (192.168.1.1) or cidr ranges (e.g. 192.168.0.0/24)
 * @method $this setWhitelist(string[] $whitelist)
 */
class Defacto_Adminfirewall_Model_Firewall extends Mage_Core_Model_Abstract
{
    /**
     * @var string[]
     */
    protected $privateIpRangeCidr = array(
        '192.168.0.0/16',
        '172.16.0.0/12',
        '10.0.0.0/8',
        '127.0.0.0/8'
    );

    /**
     * @param string $ip
     * @return bool
     */
    public function allows($ip)
    {
        $ipRanges = $this->extractCidrRanges($this->getAdminFirewallWhitelist());

        $allowed = in_array($ip, $this->getAdminFirewallWhitelist(), true);

        if ($allowed) { return true; }

        foreach ($ipRanges as $ipRange) {
            if ($allowed = $this->ipIsInCidrRange($ip, $ipRange)) { return true; }
        }

        return false;
    }

    /**
     * @param string $ip
     * @return bool
     */
    public function isPrivate($ip)
    {
        $whitelist = $this->getWhitelist();
        $this->setWhitelist($this->privateIpRangeCidr);
        $isPrivate = $this->allows($ip);
        $this->setWhitelist($whitelist);

        return $isPrivate;
    }

    /**
     * @return array
     */
    protected function getAdminFirewallWhitelist()
    {
        if ($this->hasData('whitelist') && is_array($this->getData('whitelist'))) {
            return $this->getWhitelist();
        }

        return array();
    }

    /**
     * @param string[] $firewallWhitelist
     * @return string[]
     */
    protected function extractCidrRanges($firewallWhitelist)
    {
        return array_filter($firewallWhitelist, function($haystack) { return strpos($haystack, '/') !== false; });
    }

    /**
     * @param string $ip
     * @param string $range
     * @return bool
     */
    protected function ipIsInCidrRange($ip, $range)
    {
        if (strpos($range, '/') === false) {
            throw new \InvalidArgumentException("Range $range is not in a valid valid CIDR (192.168.0.0/16) format");
        }

        list($range, $netmask) = explode('/', $range, 2);

        $rangeDec = ip2long($range);
        $ipDec = ip2long($ip);
        $wildcardDec = pow(2, (32 - $netmask)) - 1;
        $netmaskDec = ~$wildcardDec;

        return (($ipDec & $netmaskDec) == ($rangeDec & $netmaskDec));
    }
}