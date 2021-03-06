<?php

/**
 * This file is part of the PropelBundle package.
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @license    MIT License
 */
namespace Propel\Bundle\PropelAclBundle\Tests\Fixtures\Acl;

use Symfony\Component\Security\Acl\Model\AclCacheInterface;
use Symfony\Component\Security\Acl\Model\AclInterface;
use Symfony\Component\Security\Acl\Model\ObjectIdentityInterface;

class ArrayCache implements AclCacheInterface
{
    /**
     * @var AclInterface[]
     */
    public $content = array();

    /**
     * {@inheritdoc}
     */
    public function evictFromCacheById($primaryKey)
    {
        if (isset($this->content[$primaryKey])) {
            unset($this->content[$primaryKey]);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function evictFromCacheByIdentity(ObjectIdentityInterface $oid)
    {
        // Propel ACL does not make use of those.
    }

    /**
     * {@inheritdoc}
     */
    public function getFromCacheById($primaryKey)
    {
        if (isset($this->content[$primaryKey])) {
            return $this->content[$primaryKey];
        }

        return;
    }

    /**
     * {@inheritdoc}
     */
    public function getFromCacheByIdentity(ObjectIdentityInterface $oid)
    {
        // Propel ACL does not make use of those.
    }

    /**
     * {@inheritdoc}
     */
    public function putInCache(AclInterface $acl)
    {
        if (null === $acl->getId()) {
            throw new \InvalidArgumentException('The given ACL does not have an ID.');
        }

        $this->content[$acl->getId()] = $acl;
    }

    /**
     * {@inheritdoc}
     */
    public function clearCache()
    {
        $this->content = array();
    }
}
