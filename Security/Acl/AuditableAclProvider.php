<?php

/**
 * This file is part of the PropelAclBundle package.
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @license    MIT License
 */
namespace Propel\Bundle\PropelAclBundle\Security\Acl;

use Propel\Bundle\PropelAclBundle\Security\Acl\Domain\AuditableAcl;
use Symfony\Component\Security\Acl\Model\AclInterface;
use Symfony\Component\Security\Acl\Model\ObjectIdentityInterface;

/**
 * @author Toni Uebernickel <tuebernickel@gmail.com>
 */
class AuditableAclProvider extends MutableAclProvider
{
    /**
     * Creates an ACL for this provider.
     *
     * @param \PropelObjectCollection $collection
     * @param ObjectIdentityInterface $objectIdentity
     * @param array                   $loadedSecurityIdentities
     * @param AclInterface|null       $parentAcl
     * @param bool                    $inherited
     *
     * @return AuditableAcl
     */
    protected function getAcl(\PropelObjectCollection $collection, ObjectIdentityInterface $objectIdentity, array $loadedSecurityIdentities = array(), AclInterface $parentAcl = null, $inherited = true)
    {
        return new AuditableAcl($collection, $objectIdentity, $this->permissionGrantingStrategy, $loadedSecurityIdentities, $parentAcl, $inherited, $this->connection);
    }
}
