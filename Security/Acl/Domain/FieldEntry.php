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
use Symfony\Component\Security\Acl\Model\AclInterface;
use Symfony\Component\Security\Acl\Model\FieldEntryInterface;

/**
 * An ACE implementation retrieving data from a given \Propel\Bundle\PropelAclBundle\Model\Acl\Entry.
 *
 * The entry is only used to grab a "snapshot" of its data as an \Symfony\Component\Security\Acl\Model\EntryInterface is immutable!
 *
 * @see \Symfony\Component\Security\Acl\Model\EntryInterface
 *
 * @author Toni Uebernickel <tuebernickel@gmail.com>
 */
class FieldEntry extends Entry implements FieldEntryInterface
{
    /**
     * @var string
     */
    protected $field;

    /**
     * Constructor.
     *
     * @param ModelEntry   $entry
     * @param AclInterface $acl
     */
    public function __construct(ModelEntry $entry, AclInterface $acl)
    {
        $this->field = $entry->getFieldName();

        parent::__construct($entry, $acl);
    }

    /**
     * {@inheritdoc}
     */
    public function getField()
    {
        return $this->field;
    }

    /**
     * {@inheritdoc}
     */
    public function serialize()
    {
        return serialize(array(
            $this->acl,
            $this->securityIdentity,
            $this->id,
            $this->mask,
            $this->isGranting,
            $this->strategy,
            $this->auditFailure,
            $this->auditSuccess,
            $this->field,
        ));
    }

    /**
     * {@inheritdoc}
     */
    public function unserialize($serialized)
    {
        list(
            $this->acl,
            $this->securityIdentity,
            $this->id,
            $this->mask,
            $this->isGranting,
            $this->strategy,
            $this->auditFailure,
            $this->auditSuccess,
            $this->field) = unserialize($serialized);

        return $this;
    }
}
