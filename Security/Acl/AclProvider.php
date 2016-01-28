<?php

/**
 * This file is part of the PropelAclBundle package.
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @license    MIT License
 */
namespace Propel\Bundle\PropelAclBundle\Security\Acl;

use Propel\Bundle\PropelAclBundle\Model\Acl\EntryQuery;
use Propel\Bundle\PropelAclBundle\Model\Acl\ObjectIdentityQuery;
use Propel\Bundle\PropelAclBundle\Model\Acl\SecurityIdentity;
use Propel\Bundle\PropelAclBundle\Security\Acl\Domain\Acl;
use Symfony\Component\Security\Acl\Domain\ObjectIdentity;
use Symfony\Component\Security\Acl\Exception\AclNotFoundException;
use Symfony\Component\Security\Acl\Model\AclCacheInterface;
use Symfony\Component\Security\Acl\Model\AclInterface;
use Symfony\Component\Security\Acl\Model\AclProviderInterface;
use Symfony\Component\Security\Acl\Model\ObjectIdentityInterface;
use Symfony\Component\Security\Acl\Model\PermissionGrantingStrategyInterface;

/**
 * An implementation of the AclProviderInterface using Propel ORM.
 *
 * @author Toni Uebernickel <tuebernickel@gmail.com>
 */
class AclProvider implements AclProviderInterface
{
    /**
     * @var PermissionGrantingStrategyInterface
     */
    protected $permissionGrantingStrategy;

    /**
     * @var \PropelPDO|null
     */
    protected $connection;

    /**
     * @var AclCacheInterface|null
     */
    protected $cache;

    /**
     * Constructor.
     *
     * @param PermissionGrantingStrategyInterface $permissionGrantingStrategy
     * @param \PropelPDO|null                     $connection
     * @param AclCacheInterface|null              $cache
     */
    public function __construct(PermissionGrantingStrategyInterface $permissionGrantingStrategy, \PropelPDO $connection = null, AclCacheInterface $cache = null)
    {
        $this->permissionGrantingStrategy = $permissionGrantingStrategy;
        $this->connection = $connection;
        $this->cache = $cache;
    }

    /**
     * {@inheritdoc}
     */
    public function findChildren(ObjectIdentityInterface $parentObjectIdentity, $directChildrenOnly = false)
    {
        $modelIdentity = ObjectIdentityQuery::create()->findOneByAclObjectIdentity($parentObjectIdentity, $this->connection);
        if (empty($modelIdentity)) {
            return array();
        }

        if ($directChildrenOnly) {
            $collection = ObjectIdentityQuery::create()->findChildren($modelIdentity, $this->connection);
        } else {
            $collection = ObjectIdentityQuery::create()->findGrandChildren($modelIdentity, $this->connection);
        }

        $children = array();
        foreach ($collection as $eachChild) {
            $children[] = new ObjectIdentity($eachChild->getIdentifier(), $eachChild->getAclClass($this->connection)->getType());
        }

        return $children;
    }

    /**
     * {@inheritdoc}
     */
    public function findAcl(ObjectIdentityInterface $objectIdentity, array $securityIdentities = array())
    {
        $modelObj = ObjectIdentityQuery::create()->findOneByAclObjectIdentity($objectIdentity, $this->connection);
        if (null !== $this->cache and null !== $modelObj) {
            $cachedAcl = $this->cache->getFromCacheById($modelObj->getId());
            if ($cachedAcl instanceof AclInterface) {
                return $cachedAcl;
            }
        }

        $collection = EntryQuery::create()->findByAclIdentity($objectIdentity, $securityIdentities, $this->connection);

        if (0 === count($collection)) {
            if (empty($securityIdentities)) {
                $errorMessage = 'There is no ACL available for this object identity. Please create one using the MutableAclProvider.';
            } else {
                $errorMessage = 'There is at least no ACL for this object identity and the given security identities. Try retrieving the ACL without security identity filter and add ACEs for the security identities.';
            }

            throw new AclNotFoundException($errorMessage);
        }

        $loadedSecurityIdentities = array();
        foreach ($collection as $eachEntry) {
            if (!isset($loadedSecurityIdentities[$eachEntry->getSecurityIdentity()->getId()])) {
                $loadedSecurityIdentities[$eachEntry->getSecurityIdentity()->getId()] = SecurityIdentity::toAclIdentity($eachEntry->getSecurityIdentity());
            }
        }

        $parentAcl = null;
        $entriesInherited = true;

        if (null !== $modelObj) {
            $entriesInherited = $modelObj->getEntriesInheriting();
            if (null !== $modelObj->getParentObjectIdentityId()) {
                $parentObj = $modelObj->getObjectIdentityRelatedByParentObjectIdentityId($this->connection);
                try {
                    $parentAcl = $this->findAcl(new ObjectIdentity($parentObj->getIdentifier(), $parentObj->getAclClass($this->connection)->getType()));
                } catch (AclNotFoundException $e) {
                    /*
                     *  This happens e.g. if the parent ACL is created, but does not contain any ACE by now.
                     *  The ACEs may be applied later on.
                     */
                }
            }
        }

        return $this->getAcl($collection, $objectIdentity, $loadedSecurityIdentities, $parentAcl, $entriesInherited);
    }

    /**
     * {@inheritdoc}
     */
    public function findAcls(array $objectIdentities, array $securityIdentities = array())
    {
        $result = new \SplObjectStorage();
        foreach ($objectIdentities as $eachIdentity) {
            $result[$eachIdentity] = $this->findAcl($eachIdentity, $securityIdentities);
        }

        return $result;
    }

    /**
     * Creates an ACL for this provider.
     *
     * @param \PropelObjectCollection $collection
     * @param ObjectIdentityInterface $objectIdentity
     * @param array                   $loadedSecurityIdentities
     * @param AclInterface|null       $parentAcl
     * @param bool                    $inherited
     *
     * @return Acl
     */
    protected function getAcl(\PropelObjectCollection $collection, ObjectIdentityInterface $objectIdentity, array $loadedSecurityIdentities = array(), AclInterface $parentAcl = null, $inherited = true)
    {
        return new Acl($collection, $objectIdentity, $this->permissionGrantingStrategy, $loadedSecurityIdentities, $parentAcl, $inherited);
    }
}
