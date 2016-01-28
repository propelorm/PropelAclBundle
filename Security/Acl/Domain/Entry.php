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
use Propel\Bundle\PropelAclBundle\Model\Acl\SecurityIdentity;
use Symfony\Component\Security\Acl\Model\AclInterface;
use Symfony\Component\Security\Acl\Model\AuditableEntryInterface;
use Symfony\Component\Security\Acl\Model\SecurityIdentityInterface;

/**
 * An ACE implementation retrieving data from a given Propel\Bundle\PropelAclBundle\Model\Acl\Entry.
 *
 * The entry is only used to grab a "snapshot" of its data as an EntryInterface is immutable!
 *
 * @see \Symfony\Component\Security\Acl\Model\EntryInterface
 *
 * @author Toni Uebernickel <tuebernickel@gmail.com>
 */
class Entry implements AuditableEntryInterface
{
    /**
     * @var AclInterface
     */
    protected $acl;

    /**
     * @var int
     */
    protected $id;

    /**
     * @var SecurityIdentityInterface
     */
    protected $securityIdentity;

    /**
     * @var int
     */
    protected $mask;

    /**
     * @var bool
     */
    protected $isGranting;

    /**
     * @var string
     */
    protected $strategy;

    /**
     * @var bool
     */
    protected $auditSuccess;

    /**
     * @var bool
     */
    protected $auditFailure;

    /**
     * Constructor.
     *
     * @param ModelEntry   $entry
     * @param AclInterface $acl
     */
    public function __construct(ModelEntry $entry, AclInterface $acl)
    {
        $this->acl = $acl;
        $this->securityIdentity = SecurityIdentity::toAclIdentity($entry->getSecurityIdentity());

        /*
         * A new ACE (from a MutableAcl) does not have an ID,
         * but will be persisted by the MutableAclProvider afterwards, if issued.
         */
        if ($entry->getId()) {
            $this->id = $entry->getId();
        }

        $this->mask = $entry->getMask();
        $this->isGranting = $entry->getGranting();
        $this->strategy = $entry->getGrantingStrategy();
        $this->auditFailure = $entry->getAuditFailure();
        $this->auditSuccess = $entry->getAuditSuccess();
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
            $this->auditSuccess) = unserialize($serialized);

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getAcl()
    {
        return $this->acl;
    }

    /**
     * {@inheritdoc}
     */
    public function getSecurityIdentity()
    {
        return $this->securityIdentity;
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
    public function getMask()
    {
        return $this->mask;
    }

    /**
     * {@inheritdoc}
     */
    public function getStrategy()
    {
        return $this->strategy;
    }

    /**
     * {@inheritdoc}
     */
    public function isGranting()
    {
        return $this->isGranting;
    }

    /**
     * {@inheritdoc}
     */
    public function isAuditFailure()
    {
        return $this->auditFailure;
    }

    /**
     * {@inheritdoc}
     */
    public function isAuditSuccess()
    {
        return $this->auditSuccess;
    }
}
