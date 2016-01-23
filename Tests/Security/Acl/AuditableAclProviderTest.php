<?php

/**
 * This file is part of the PropelAclBundle package.
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @license    MIT License
 */
namespace Propel\Bundle\PropelAclBundle\Tests\Security\Acl;

use Propel\Bundle\PropelAclBundle\Model\Acl\EntryQuery;
use Propel\Bundle\PropelAclBundle\Security\Acl\AuditableAclProvider;
use Propel\Bundle\PropelAclBundle\Tests\TestCase;
use Symfony\Component\Security\Acl\Domain\PermissionGrantingStrategy;

/**
 * @author Toni Uebernickel <tuebernickel@gmail.com>
 */
class AuditableAclProviderTest extends TestCase
{
    public function testCreateAcl()
    {
        $acl = $this->getAclProvider()->createAcl($this->getAclObjectIdentity(1));

        $this->assertNotEmpty($acl);
        $this->assertInstanceOf('Propel\Bundle\PropelAclBundle\Security\Acl\Domain\AuditableAcl', $acl);
        $this->assertEquals(1, $acl->getId());
    }

    /**
     * @depends testCreateAcl
     */
    public function testUpdatePersistsAuditing()
    {
        $acl = $this->getAclProvider()->createAcl($this->getAclObjectIdentity(1));
        $acl->insertObjectAce($this->getRoleSecurityIdentity(), 64);
        $this->getAclProvider()->updateAcl($acl);

        $entries = EntryQuery::create()->find($this->con);
        $this->assertCount(1, $entries);
        // default values
        $this->assertFalse($entries[0]->getAuditSuccess());
        $this->assertTrue($entries[0]->getAuditFailure());

        $acl->updateObjectAuditing(0, true, true);
        $this->getAclProvider()->updateAcl($acl);

        $entries = EntryQuery::create()->find($this->con);
        $this->assertCount(1, $entries);
        $this->assertTrue($entries[0]->getAuditSuccess());
        $this->assertTrue($entries[0]->getAuditFailure());

        $acl->updateObjectAuditing(0, false, true);
        $this->getAclProvider()->updateAcl($acl);

        $entries = EntryQuery::create()->find($this->con);
        $this->assertCount(1, $entries);
        $this->assertFalse($entries[0]->getAuditSuccess());
        $this->assertTrue($entries[0]->getAuditFailure());

        $acl->updateObjectAuditing(0, true, false);
        $this->getAclProvider()->updateAcl($acl);

        $entries = EntryQuery::create()->find($this->con);
        $this->assertCount(1, $entries);
        $this->assertTrue($entries[0]->getAuditSuccess());
        $this->assertFalse($entries[0]->getAuditFailure());

        $acl->updateObjectAuditing(0, false, false);
        $this->getAclProvider()->updateAcl($acl);

        $entries = EntryQuery::create()->find($this->con);
        $this->assertCount(1, $entries);
        $this->assertFalse($entries[0]->getAuditSuccess());
        $this->assertFalse($entries[0]->getAuditFailure());
    }

    protected function getAclProvider()
    {
        return new AuditableAclProvider(new PermissionGrantingStrategy(), $this->con);
    }
}
