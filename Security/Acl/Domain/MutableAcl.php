<?php

/**
 * This file is part of the PropelAclBundle package.
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @license    MIT License
 */
namespace Propel\Bundle\PropelAclBundle\Security\Acl\Domain;

use Propel\Bundle\PropelAclBundle\Model\Acl\Entry as ModelEntry;
use Propel\Bundle\PropelAclBundle\Model\Acl\ObjectIdentity;
use Propel\Bundle\PropelAclBundle\Model\Acl\ObjectIdentityQuery;
use Propel\Bundle\PropelAclBundle\Model\Acl\SecurityIdentity;
use Symfony\Component\Security\Acl\Domain\PermissionGrantingStrategy;
use Symfony\Component\Security\Acl\Model\AclInterface;
use Symfony\Component\Security\Acl\Model\MutableAclInterface;
use Symfony\Component\Security\Acl\Model\ObjectIdentityInterface;
use Symfony\Component\Security\Acl\Model\PermissionGrantingStrategyInterface;
use Symfony\Component\Security\Acl\Model\SecurityIdentityInterface;

/**
 * @author Toni Uebernickel <tuebernickel@gmail.com>
 */
class MutableAcl extends Acl implements MutableAclInterface
{
    /**
     * The id of the current ACL.
     *
     * It's the id of the ObjectIdentity model.
     *
     * @var int
     */
    protected $id;

    /**
     * A reference to the ObjectIdentity this ACL is mapped to.
     *
     * @var ObjectIdentity
     */
    protected $modelObjectIdentity;

    /**
     * A connection to be used for all changes on the ACL.
     *
     * @var \PropelPDO|null
     */
    protected $con;

    /**
     * Constructor.
     *
     * @param \PropelObjectCollection             $entries
     * @param ObjectIdentityInterface             $objectIdentity
     * @param PermissionGrantingStrategyInterface $permissionGrantingStrategy
     * @param array                               $loadedSecurityIdentities
     * @param AclInterface|null                   $parentAcl
     * @param bool                                $inherited
     * @param \PropelPDO|null                     $con
     */
    public function __construct(\PropelObjectCollection $entries, ObjectIdentityInterface $objectIdentity, PermissionGrantingStrategyInterface $permissionGrantingStrategy, array $loadedSecurityIdentities = array(), AclInterface $parentAcl = null, $inherited = true, \PropelPDO $con = null)
    {
        parent::__construct($entries, $objectIdentity, $permissionGrantingStrategy, $loadedSecurityIdentities, $parentAcl, $inherited);

        $this->modelObjectIdentity = ObjectIdentityQuery::create()
            ->filterByAclObjectIdentity($objectIdentity, $con)
            ->findOneOrCreate($con)
        ;

        if ($this->modelObjectIdentity->isNew()) {
            $this->modelObjectIdentity->save($con);
        }

        $this->id = $this->modelObjectIdentity->getId();

        $this->con = $con;
    }

    /**
     * {@inheritdoc}
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * {@inheritdoc}
     */
    public function setEntriesInheriting($boolean)
    {
        $this->inherited = $boolean;
    }

    /**
     * {@inheritdoc}
     */
    public function setParentAcl(AclInterface $acl = null)
    {
        $this->parentAcl = $acl;
    }

    /**
     * {@inheritdoc}
     */
    public function deleteClassAce($index)
    {
        $this->deleteIndex($this->classAces, $index);
    }

    /**
     * {@inheritdoc}
     */
    public function deleteClassFieldAce($index, $field)
    {
        $this
            ->validateField($this->classFieldAces, $field)
            ->deleteIndex($this->classFieldAces[$field], $index)
        ;
    }

    /**
     * {@inheritdoc}
     */
    public function deleteObjectAce($index)
    {
        $this->deleteIndex($this->objectAces, $index);
    }

    /**
     * {@inheritdoc}
     */
    public function deleteObjectFieldAce($index, $field)
    {
        $this
            ->validateField($this->objectFieldAces, $field)
            ->deleteIndex($this->objectFieldAces[$field], $index)
        ;
    }

    /**
     * {@inheritdoc}
     */
    public function insertClassAce(SecurityIdentityInterface $securityIdentity, $mask, $index = 0, $granting = true, $strategy = null)
    {
        $this->insertToList($this->classAces, $index, $this->createAce($mask, $index, $securityIdentity, $strategy, $granting));
    }

    /**
     * {@inheritdoc}
     */
    public function insertClassFieldAce($field, SecurityIdentityInterface $securityIdentity, $mask, $index = 0, $granting = true, $strategy = null)
    {
        if (!isset($this->classFieldAces[$field])) {
            $this->classFieldAces[$field] = array();
        }

        $this->insertToList($this->classFieldAces[$field], $index, $this->createAce($mask, $index, $securityIdentity, $strategy, $granting, $field));
    }

    /**
     * {@inheritdoc}
     */
    public function insertObjectAce(SecurityIdentityInterface $securityIdentity, $mask, $index = 0, $granting = true, $strategy = null)
    {
        $this->insertToList($this->objectAces, $index, $this->createAce($mask, $index, $securityIdentity, $strategy, $granting));
    }

    /**
     * {@inheritdoc}
     */
    public function insertObjectFieldAce($field, SecurityIdentityInterface $securityIdentity, $mask, $index = 0, $granting = true, $strategy = null)
    {
        if (!isset($this->objectFieldAces[$field])) {
            $this->objectFieldAces[$field] = array();
        }

        $this->insertToList($this->objectFieldAces[$field], $index, $this->createAce($mask, $index, $securityIdentity, $strategy, $granting, $field));
    }

    /**
     * {@inheritdoc}
     */
    public function updateClassAce($index, $mask, $strategy = null)
    {
        $this->updateAce($this->classAces, $index, $mask, $strategy);
    }

    /**
     * {@inheritdoc}
     */
    public function updateClassFieldAce($index, $field, $mask, $strategy = null)
    {
        $this
            ->validateField($this->classFieldAces, $field)
            ->updateAce($this->classFieldAces[$field], $index, $mask, $strategy)
        ;
    }

    /**
     * {@inheritdoc}
     */
    public function updateObjectAce($index, $mask, $strategy = null)
    {
        $this->updateAce($this->objectAces, $index, $mask, $strategy);
    }

    /**
     * {@inheritdoc}
     */
    public function updateObjectFieldAce($index, $field, $mask, $strategy = null)
    {
        $this->validateField($this->objectFieldAces, $field);
        $this->updateAce($this->objectFieldAces[$field], $index, $mask, $strategy);
    }

    /**
     * {@inheritdoc}
     */
    public function serialize()
    {
        return serialize(array(
            $this->id,
            $this->modelObjectIdentity,
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
            $this->id,
            $this->modelObjectIdentity,
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
     * Inserts a given entry into the list on the given index by shifting all others.
     *
     * @param array $list
     * @param int   $index
     * @param Entry $entry
     *
     * @return MutableAcl
     */
    protected function insertToList(array &$list, $index, Entry $entry)
    {
        $this->isWithinBounds($list, $index);

        if ($entry instanceof FieldEntry) {
            $this->updateFields($entry->getField());
        }

        $list = array_merge(
            array_slice($list, 0, $index),
            array($entry),
            array_splice($list, $index)
        );

        return $this;
    }

    /**
     * Updates a single ACE of this ACL.
     *
     * @param array       $list
     * @param int         $index
     * @param int         $mask
     * @param string|null $strategy
     *
     * @return MutableAcl
     */
    protected function updateAce(array &$list, $index, $mask, $strategy = null)
    {
        $this->validateIndex($list, $index);

        $entry = ModelEntry::fromAclEntry($list[$index]);

        // Apply updates
        $entry->setMask($mask);
        if (null !== $strategy) {
            $entry->setGrantingStrategy($strategy);
        }

        $list[$index] = ModelEntry::toAclEntry($entry, $this);

        return $this;
    }

    /**
     * Deletes the ACE of the given list and index.
     *
     * The list will be re-ordered to have a valid 0..x list.
     *
     * @param array $list
     * @param int   $index
     *
     * @return MutableAcl
     */
    protected function deleteIndex(array &$list, $index)
    {
        $this->validateIndex($list, $index);
        unset($list[$index]);
        $this->reorderList($list, $index - 1);

        return $this;
    }

    /**
     * Validates the index on the given list of ACEs.
     *
     * @throws \OutOfBoundsException
     *
     * @param array $list
     * @param int   $index
     *
     * @return MutableAcl
     */
    protected function isWithinBounds(array &$list, $index)
    {
        // No count()-1, the count is one ahead of index, and could create the next valid entry!
        if ($index < 0 or $index > count($list)) {
            throw new \OutOfBoundsException(sprintf('The index must be in the interval [0, %d].', count($list)));
        }

        return $this;
    }

    /**
     * Checks the index for existence in the given list.
     *
     * @throws \OutOfBoundsException
     *
     * @param array $list
     * @param $index
     *
     * @return MutableAcl
     */
    protected function validateIndex(array &$list, $index)
    {
        if (!isset($list[$index])) {
            throw new \OutOfBoundsException(sprintf('The index "%d" does not exist.', $index));
        }

        return $this;
    }

    /**
     * Validates the given field to be present.
     *
     * @throws \InvalidArgumentException
     *
     * @param array  $list
     * @param string $field
     *
     * @return MutableAcl
     */
    protected function validateField(array &$list, $field)
    {
        if (!isset($list[$field])) {
            throw new \InvalidArgumentException(sprintf('The given field "%s" does not exist.', $field));
        }

        return $this;
    }

    /**
     * Orders the given list to have numeric indexes from 0..x.
     *
     * @param array $list
     * @param int   $index The right boundary to which the list is valid.
     *
     * @return MutableAcl
     */
    protected function reorderList(array &$list, $index)
    {
        $list = array_merge(
            array_slice($list, 0, $index + 1), // +1 to get length
            array_splice($list, $index + 1)    // +1 to get first index to re-order
        );

        return $this;
    }

    /**
     * Creates a new ACL Entry.
     *
     * @param int                       $mask
     * @param int                       $index
     * @param SecurityIdentityInterface $securityIdentity
     * @param string                    $strategy
     * @param bool                      $granting
     * @param string                    $field
     *
     * @return Entry|FieldEntry
     */
    protected function createAce($mask, $index, SecurityIdentityInterface $securityIdentity, $strategy = null, $granting = true, $field = null)
    {
        if (!is_int($mask)) {
            throw new \InvalidArgumentException('The given mask is not valid. Please provide an integer.');
        }

        // Compatibility with default implementation
        if (null === $strategy) {
            if (true === $granting) {
                $strategy = PermissionGrantingStrategy::ALL;
            } else {
                $strategy = PermissionGrantingStrategy::ANY;
            }
        }

        $model = new ModelEntry();
        $model
            ->setAceOrder($index)
            ->setMask($mask)
            ->setGrantingStrategy($strategy)
            ->setGranting($granting)
            ->setSecurityIdentity(SecurityIdentity::fromAclIdentity($securityIdentity))
        ;

        if (null !== $field) {
            $model->setFieldName($field);

            return new FieldEntry($model, $this);
        }

        return new Entry($model, $this);
    }
}
