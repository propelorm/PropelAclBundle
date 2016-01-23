<?php

/**
 * This file is part of the PropelAclBundle package.
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @license    MIT License
 */
namespace Propel\Bundle\PropelAclBundle\Tests;

use Propel\Bundle\PropelAclBundle\Model\Acl\AclClass;
use Propel\Bundle\PropelAclBundle\Model\Acl\Entry;
use Propel\Bundle\PropelAclBundle\Model\Acl\ObjectIdentity as ModelObjectIdentity;
use Propel\Bundle\PropelAclBundle\Security\Acl\MutableAclProvider;
use Symfony\Component\Security\Acl\Domain\ObjectIdentity;
use Symfony\Component\Security\Acl\Domain\PermissionGrantingStrategy;
use Symfony\Component\Security\Acl\Domain\RoleSecurityIdentity;
use Symfony\Component\Security\Core\Role\Role;

/**
 * The base class for test cases of the PropelAclBundle.
 *
 * @author Toni Uebernickel <tuebernickel@gmail.com>
 */
abstract class TestCase extends \PHPUnit_Framework_TestCase
{
    protected $con = null;
    protected $cache = null;

    public static function setUpBeforeClass()
    {
        if (!class_exists('Propel')) {
            self::markTestSkipped('Propel is not available.');
        }
    }

    public function setUp()
    {
        parent::setUp();

        $schema = file_get_contents(__DIR__.'/../Resources/config/propel/acl_schema.xml');

        $builder = new \PropelQuickBuilder();
        $builder->setSchema($schema);
        if (!class_exists('Propel\Bundle\PropelAclBundle\Model\Acl\map\AclClassTableMap')) {
            $builder->setClassTargets(array('tablemap', 'peer', 'object', 'query'));
        } else {
            $builder->setClassTargets(array());
        }

        $this->con = $builder->build();
    }

    /**
     * @return \Propel\Bundle\PropelAclBundle\Model\Acl\ObjectIdentity
     */
    protected function createModelObjectIdentity($identifier)
    {
        $aclClass = $this->getAclClass();
        $objIdentity = new ModelObjectIdentity();

        $this->assertTrue((bool) $objIdentity
            ->setAclClass($aclClass)
            ->setIdentifier($identifier)
            ->save($this->con)
        );

        return $objIdentity;
    }

    protected function createEntry()
    {
        $entry = new Entry();
        $entry
            ->setAuditSuccess(false)
            ->setAuditFailure(false)
            ->setMask(64)
            ->setGranting(true)
            ->setGrantingStrategy('all')
            ->setAceOrder(0)
        ;

        return $entry;
    }

    protected function getAclClass()
    {
        return AclClass::fromAclObjectIdentity($this->getAclObjectIdentity(), $this->con);
    }

    protected function getAclProvider()
    {
        return new MutableAclProvider(new PermissionGrantingStrategy(), $this->con, $this->cache);
    }

    protected function getAclObjectIdentity($identifier = 1)
    {
        return new ObjectIdentity($identifier, 'Propel\Bundle\PropelAclBundle\Tests\Fixtures\Model\Book');
    }

    protected function getRoleSecurityIdentity($role = 'ROLE_USER')
    {
        return new RoleSecurityIdentity(new Role($role));
    }
}
