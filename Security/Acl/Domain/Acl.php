<?php

/**
 * This file is part of the PropelAclBundle package.
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @license    MIT License
 */
namespace Propel\Bundle\PropelAclBundle\Security\Acl\Domain;

use Symfony\Component\Security\Acl\Exception\Exception as AclException;
use Symfony\Component\Security\Acl\Model\AclInterface;
use Symfony\Component\Security\Acl\Model\ObjectIdentityInterface;
use Symfony\Component\Security\Acl\Model\PermissionGrantingStrategyInterface;
use Symfony\Component\Security\Acl\Model\SecurityIdentityInterface;

/**
 * An ACL implementation that is immutable based on data from a PropelObjectCollection of Propel\Bundle\PropelAclBundle\Model\Acl\Entry.
 *
 * @author Toni Uebernickel <tuebernickel@gmail.com>
 */
class Acl implements AclInterface
{
    protected $model = 'Propel\Bundle\PropelAclBundle\Model\Acl\Entry';

    /**
     * @var Entry[]
     */
    protected $classAces = array();

    /**
     * @var FieldEntry[]
     */
    protected $classFieldAces = array();

    /**
     * @var Entry[]
     */
    protected $objectAces = array();

    /**
     * @var FieldEntry[]
     */
    protected $objectFieldAces = array();

    /**
     * @var ObjectIdentityInterface
     */
    protected $objectIdentity;

    /**
     * @var AclInterface|null
     */
    protected $parentAcl;

    /**
     * @var PermissionGrantingStrategyInterface
     */
    protected $permissionGrantingStrategy;

    /**
     * @var bool
     */
    protected $inherited;

    /**
     * @var SecurityIdentityInterface[]
     */
    protected $loadedSecurityIdentities = array();

    /**
     * A list of known associated fields on this ACL.
     *
     * @var string[]
     */
    protected $fields = array();

    /**
     * Constructor.
     *
     * @param \PropelObjectCollection             $entries
     * @param ObjectIdentityInterface             $objectIdentity
     * @param PermissionGrantingStrategyInterface $permissionGrantingStrategy
     * @param array                               $loadedSecurityIdentities
     * @param AclInterface|null                   $parentAcl
     * @param bool                                $inherited
     */
    public function __construct(\PropelObjectCollection $entries, ObjectIdentityInterface $objectIdentity, PermissionGrantingStrategyInterface $permissionGrantingStrategy, array $loadedSecurityIdentities = array(), AclInterface $parentAcl = null, $inherited = true)
    {
        if ($entries->getModel() !== $this->model) {
            throw new AclException(sprintf('The given collection does not contain models of class "%s" but of class "%s".', $this->model, $entries->getModel()));
        }

        foreach ($entries as $eachEntry) {
            if (null === $eachEntry->getFieldName() and null === $eachEntry->getObjectIdentityId()) {
                $this->classAces[] = new Entry($eachEntry, $this);
            }

            if (null !== $eachEntry->getFieldName() and null === $eachEntry->getObjectIdentityId()) {
                if (empty($this->classFieldAces[$eachEntry->getFieldName()])) {
                    $this->classFieldAces[$eachEntry->getFieldName()] = array();
                    $this->updateFields($eachEntry->getFieldName());
                }

                $this->classFieldAces[$eachEntry->getFieldName()][] = new FieldEntry($eachEntry, $this);
            }

            if (null === $eachEntry->getFieldName() and null !== $eachEntry->getObjectIdentityId()) {
                $this->objectAces[] = new Entry($eachEntry, $this);
            }

            if (null !== $eachEntry->getFieldName() and null !== $eachEntry->getObjectIdentityId()) {
                if (empty($this->objectFieldAces[$eachEntry->getFieldName()])) {
                    $this->objectFieldAces[$eachEntry->getFieldName()] = array();
                    $this->updateFields($eachEntry->getFieldName());
                }

                $this->objectFieldAces[$eachEntry->getFieldName()][] = new FieldEntry($eachEntry, $this);
            }
        }

        $this->objectIdentity = $objectIdentity;
        $this->permissionGrantingStrategy = $permissionGrantingStrategy;
        $this->parentAcl = $parentAcl;
        $this->inherited = $inherited;
        $this->loadedSecurityIdentities = $loadedSecurityIdentities;

        $this->fields = array_unique($this->fields);
    }

    /**
     * {@inheritdoc}
     */
    public function getClassAces()
    {
        return $this->classAces;
    }

    /**
     * {@inheritdoc}
     */
    public function getClassFieldAces($field)
    {
        return isset($this->classFieldAces[$field]) ? $this->classFieldAces[$field] : array();
    }

    /**
     * {@inheritdoc}
     */
    public function getObjectAces()
    {
        return $this->objectAces;
    }

    /**
     * {@inheritdoc}
     */
    public function getObjectFieldAces($field)
    {
        return isset($this->objectFieldAces[$field]) ? $this->objectFieldAces[$field] : array();
    }

    /**
     * {@inheritdoc}
     */
    public function getObjectIdentity()
    {
        return $this->objectIdentity;
    }

    /**
     * {@inheritdoc}
     */
    public function getParentAcl()
    {
        return $this->parentAcl;
    }

    /**
     * {@inheritdoc}
     */
    public function isEntriesInheriting()
    {
        return $this->inherited;
    }

    /**
     * {@inheritdoc}
     */
    public function isFieldGranted($field, array $masks, array $securityIdentities, $administrativeMode = false)
    {
        return $this->permissionGrantingStrategy->isFieldGranted($this, $field, $masks, $securityIdentities, $administrativeMode);
    }

    /**
     * {@inheritdoc}
     */
    public function isGranted(array $masks, array $securityIdentities, $administrativeMode = false)
    {
        return $this->permissionGrantingStrategy->isGranted($this, $masks, $securityIdentities, $administrativeMode);
    }

    /**
     * {@inheritdoc}
     */
    public function isSidLoaded($securityIdentities)
    {
        if (!is_array($securityIdentities)) {
            $securityIdentities = array($securityIdentities);
        }

        $found = 0;
        foreach ($securityIdentities as $eachSecurityIdentity) {
            if (!$eachSecurityIdentity instanceof SecurityIdentityInterface) {
                throw new \InvalidArgumentException('At least one entry of the given list is not implementing the "SecurityIdentityInterface".');
            }

            foreach ($this->loadedSecurityIdentities as $eachLoadedIdentity) {
                if ($eachSecurityIdentity->equals($eachLoadedIdentity)) {
                    ++$found;

                    break;
                }
            }
        }

        return $found === count($securityIdentities);
    }

    /**
     * {@inheritdoc}
     */
    public function serialize()
    {
        return serialize(array(
            $this->model,
            $this->classAces,
            $this->classFieldAces,
            $this->objectAces,
            $this->objectFieldAces,
            $this->objectIdentity,
            $this->parentAcl,
            $this->permissionGrantingStrategy,
            $this->inherited,
            $this->loadedSecurityIdentities,
        ));
    }

    /**
     * {@inheritdoc}
     */
    public function unserialize($serialized)
    {
        list(
            $this->model,
            $this->classAces,
            $this->classFieldAces,
            $this->objectAces,
            $this->objectFieldAces,
            $this->objectIdentity,
            $this->parentAcl,
            $this->permissionGrantingStrategy,
            $this->inherited,
            $this->loadedSecurityIdentities) = unserialize($serialized);

        return $this;
    }

    /**
     * Returns a list of associated fields on this ACL.
     *
     * @return array
     */
    public function getFields()
    {
        return $this->fields;
    }

    /**
     * Updates the internal list of associated fields on this ACL.
     *
     * @param string $field
     *
     * @return Acl
     */
    protected function updateFields($field)
    {
        if (!in_array($field, $this->fields)) {
            $this->fields[] = $field;
        }

        return $this;
    }
}
