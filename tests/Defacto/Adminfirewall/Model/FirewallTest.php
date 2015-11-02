<?php

class Defacto_Adminfirewall_Model_FirewallTest extends MageTest_PHPUnit_Framework_TestCase
{
    public function testVerifiesClientIpIsInWhitelist()
    {
        $whitelist = array('203.55.240.1');
        $firewall = Mage::getModel('defacto_adminfirewall/firewall', array('whitelist' => $whitelist));
        $this->assertTrue($firewall->allows('203.55.240.1'));
        $this->assertFalse($firewall->allows('203.55.240.2'));
    }

    public function testVerifiesClientIpIsWithinCidrRange()
    {
        $whitelist = array('192.168.0.0/16');

        $firewall = Mage::getModel('defacto_adminfirewall/firewall', array('whitelist' => $whitelist));
        $this->assertTrue($firewall->allows('192.168.0.1'));
        $this->assertFalse($firewall->allows('192.167.0.1'));
    }

    public function testVerifiesClientIpIsWithinPrivateIpRange()
    {
        $firewall = Mage::getModel('defacto_adminfirewall/firewall');
        $this->assertTrue($firewall->isPrivate('127.0.0.1'));
        $this->assertTrue($firewall->isPrivate('192.168.0.1'));
        $this->assertTrue($firewall->isPrivate('172.16.100.1'));
        $this->assertTrue($firewall->isPrivate('10.10.10.10'));
        $this->assertTrue($firewall->isPrivate('127.0.0.1'));

        $this->assertFalse($firewall->isPrivate('8.8.8.8'));
        $this->assertFalse($firewall->isPrivate('192.167.0.1'));
        $this->assertFalse($firewall->isPrivate('172.13.17.1'));
    }
}