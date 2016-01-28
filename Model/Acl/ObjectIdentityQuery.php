<?php

/**
 * This file is part of the PropelAclBundle package.
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @license    MIT License
 */
namespace Propel\Bundle\PropelAclBundle\Model\Acl;

use Propel\Bundle\PropelAclBundle\Model\Acl\om\BaseObjectIdentityQuery;
use Symfony\Component\Security\Acl\Model\ObjectIdentityInterface;

class ObjectIdentityQuery extends BaseObjectIdentityQuery
{
    /**
     * Filters by an ObjectIdentity object belonging to the given ACL related ObjectIdentity.
     *
     * @param ObjectIdentityInterface $objectIdentity
     * @param \PropelPDO|null         $con
     *
     * @return ObjectIdentityQuery
     */
    public function filterByAclObjectIdentity(ObjectIdentityInterface $objectIdentity, \PropelPDO $con = null)
    {
        /*
         * Not using a JOIN here, because the filter may be applied on 'findOneOrCreate',
         * which is currently (Propel 1.6.4-dev) not working.
         */
        $aclClass = AclClass::fromAclObjectIdentity($objectIdentity, $con);
        $this
            ->filterByClassId($aclClass->getId())
            ->filterByIdentifier($objectIdentity->getIdentifier())
        ;

        return $this;
    }

    /**
     * Returns an ObjectIdentity object belonging to the given ACL related ObjectIdentity.
     *
     * @param ObjectIdentityInterface $objectIdentity
     * @param \PropelPDO|null         $con
     *
     * @return ObjectIdentity
     */
    public function findOneByAclObjectIdentity(ObjectIdentityInterface $objectIdentity, \PropelPDO $con = null)
    {
        return $this
            ->filterByAclObjectIdentity($objectIdentity, $con)
            ->findOne($con)
        ;
    }

    /**
     * Returns all children of the given object identity.
     *
     * @param ObjectIdentity  $objectIdentity
     * @param \PropelPDO|null $con
     *
     * @return \PropelObjectCollection
     */
    public function findChildren(ObjectIdentity $objectIdentity, \PropelPDO $con = null)
    {
        return $this
            ->filterByObjectIdentityRelatedByParentObjectIdentityId($objectIdentity)
            ->find($con)
        ;
    }

    /**
     * Return all children and grand-children of the given object identity.
     *
     * @param ObjectIdentity  $objectIdentity
     * @param \PropelPDO|null $con
     *
     * @return \PropelObjectCollection
     */
    public function findGrandChildren(ObjectIdentity $objectIdentity, \PropelPDO $con = null)
    {
        return $this
            ->useObjectIdentityAncestorRelatedByObjectIdentityIdQuery()
                ->filterByObjectIdentityRelatedByAncestorId($objectIdentity)
                ->filterByObjectIdentityRelatedByObjectIdentityId($objectIdentity, \Criteria::NOT_EQUAL)
            ->endUse()
            ->find($con)
        ;
    }

    /**
     * Return all ancestors of the given object identity.
     *
     * @param ObjectIdentity  $objectIdentity
     * @param \PropelPDO|null $con
     *
     * @return \PropelObjectCollection
     */
    public function findAncestors(ObjectIdentity $objectIdentity, \PropelPDO $con = null)
    {
        return $this
            ->useObjectIdentityAncestorRelatedByAncestorIdQuery()
                ->filterByObjectIdentityRelatedByObjectIdentityId($objectIdentity)
                ->filterByObjectIdentityRelatedByAncestorId($objectIdentity, \Criteria::NOT_EQUAL)
            ->endUse()
            ->find($con)
        ;
    }
}
