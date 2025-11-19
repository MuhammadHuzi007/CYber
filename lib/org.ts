import { prisma } from './prisma'

export async function createDefaultOrgForUser(userId: string, userEmail: string) {
  // Generate a unique slug from email
  const baseSlug = userEmail.split('@')[0].toLowerCase().replace(/[^a-z0-9]/g, '-')
  let slug = baseSlug
  let counter = 1

  // Ensure slug is unique
  while (await prisma.organization.findUnique({ where: { slug } })) {
    slug = `${baseSlug}-${counter}`
    counter++
  }

  // Create organization
  const org = await prisma.organization.create({
    data: {
      name: `${userEmail.split('@')[0]}'s Organization`,
      slug,
      members: {
        create: {
          userId,
          role: 'OWNER',
        },
      },
    },
  })

  return org
}

export async function getUserOrgs(userId: string) {
  return prisma.organization.findMany({
    where: {
      members: {
        some: {
          userId,
        },
      },
    },
    include: {
      members: {
        where: {
          userId,
        },
      },
    },
    orderBy: {
      createdAt: 'asc',
    },
  })
}

export async function getOrgMember(userId: string, orgId: string) {
  return prisma.orgMember.findUnique({
    where: {
      userId_orgId: {
        userId,
        orgId,
      },
    },
  })
}

